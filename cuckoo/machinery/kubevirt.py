# Copyright (C) 2015-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by the Canadian Centre for
# Cyber Security to support KubeVirt on Rancher.

import logging
import threading

from sqlalchemy.exc import SQLAlchemyError

import kubevirt
from kubevirt.rest import ApiException

from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class KubeVirt(Machinery):
    """Virtualization layer for KubeVirt."""

    # Virtual Machine Instance (VMI) phases.
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    UNKNOWN = "Unknown"
    ERROR = "Error"

    def __init__(self):
        super(KubeVirt, self).__init__()

    def _initialize(self, module_name):
        """
        Initializing instance parameters.
        @param module_name: module name
        """
        super(KubeVirt, self)._initialize(module_name)

        self.kubevirt_machines = {}
        self.machine_queue = []
        self.dynamic_machines_sequence = 0
        self.dynamic_machines_count = 0
        self.initializing = True

        log.debug(
            "Connecting to KubeVirt for the namespace '%s'.",
            self.options.kubevirt.namespace
        )

        # Configure API key authorization: BearerToken.
        kubevirt.configuration.api_key['authorization'] = 'YOUR_API_KEY'

        # Create an instance of the API class.
        self.api_instance = kubevirt.DefaultApi()

    def _initialize_check(self):
        """
        Run all checks when a machine manager is initialized.
        @raise CuckooMachineError: if KubeVirt call does not work.
        """
        # Base checks.
        super(KubeVirt, self)._initialize_check()

        try:
            log.debug("Retrieving all virtual machine instances in namespace.")
            instances = self.api_instance.list_namespaced_virtual_machine(
                self.options.kubevirt.namespace
            )
            for instance in instances:
                # Cleaning up instances from previous Cuckoo runs.
                self._delete_instance(instance)
        except ApiException as exc:
            log.error(
                "Exception when calling DefaultApi->list_namespaced_" +
                "virtual_machine: '%s'.",
                exc
            )
            raise CuckooMachineError(exc)

        # Create the required amount of instances as specified in kubevirt.conf.
        self._create_and_start_machines()

        # The system is now no longer in the initializing phase.
        self.initializing = False

    def _delete_machine_from_db(self, label):
        """
        Implementing machine deletion from Cuckoo's database.
        @param label: the machine name
        """
        session = self.db.Session()
        try:
            from cuckoo.core.database import Machine
            machine = session.query(Machine).filter_by(label=label).first()
            if machine:
                session.delete(machine)
                session.commit()
        except SQLAlchemyError as exc:
            log.debug("Database error removing machine: '%s'.", exc)
            session.rollback()
            return
        finally:
            session.close()

    def _create_and_start_machines(self):
        """
        Based on the "gap" in az.conf, ensure that there are x machines to be
        created
        if there are less available machines than the gap.
        """
        # Read configuration file.
        machinery_options = self.options.kubevirt

        current_available_machines = self.db.count_machines_available()
        running_machines_gap = machinery_options.get("running_machines_gap", 0)
        dynamic_machines_limit = machinery_options["dynamic_machines_limit"]

        # If there are no available machines left  -> launch a new machine.
        threads = []
        while current_available_machines < running_machines_gap:
            if self.dynamic_machines_count >= dynamic_machines_limit:
                log.debug(
                    "Reached dynamic machines limit - %d machines",
                    dynamic_machines_limit
                )
                break
            else:
                # Using threads to create machines in parallel.
                self.dynamic_machines_count += 1
                thr = threading.Thread(target=self._allocate_new_machine)
                threads.append(thr)
                thr.start()
                current_available_machines += 1

        # Waiting for all machines to finish being created,
        # depending on the system state.
        if self.initializing:
            for thr in threads:
                thr.join()

    def _allocate_new_machine(self):
        """
        Creating new KubeVirt VMI. The process is as follows:
        - Create instance
        - If all goes well, add machine to database
        @return: Signals to thread that method is finished.
        @raise CuckooMachineError: if KubeVirt call does not work.
        """
        # Read configuration file.
        machinery_options = self.options.kubevirt

        self.dynamic_machines_sequence += 1
        new_machine_name = "vmicuckooguest%03d" % self.dynamic_machines_sequence

        # Avoiding collision on machine name if machine is still deleting.
        instance_names = self._list()
        for instance in instance_names:
            while instance == new_machine_name:
                self.dynamic_machines_sequence = \
                    self.dynamic_machines_sequence + 1
                new_machine_name = \
                    "vmicuckooguest%03d" % self.dynamic_machines_sequence

        try:
            vmi = read_yaml_file(machinery_options.image_yaml)
            machine = \
                self.api_instance.create_namespaced_virtual_machine_instance(
                    vmi,
                    machinery_options.namespace
                )
        except ApiException as exc:
            log.error(
                "Exception when calling DefaultApi->create_namespaced_" +
                "virtual_machine_instance: '%s'.",
                exc
            )
            raise CuckooMachineError(exc)

        # There are occasions where KubeVirt fails to create an instance.
        if not machine:
            # Decrementing the count, so that the method caller will try again.
            self.dynamic_machines_count -= 1
            return

        print(machine.status.interfaces)
        nic_private_ip = machine.status.interfaces[0].ip_address

        log.info(
            "Allocating a new machine '%s' to meet pool size requirements.",
            new_machine_name
        )
        self.machine_queue.append(new_machine_name)
        self.azure_machines[new_machine_name] = machine

        # Sets "new_machine" object in configuration object to avoid
        # raising an exception.
        setattr(self.options, new_machine_name, {})

        # Add machine to DB
        # TODO: find these fields
        self.db.add_machine(
            name=machine.metadata.name,
            label=machine.metadata.name,
            ip=nic_private_ip,
            platform=machinery_options.get("platform"),
            options=machinery_options.get("options"),
            tags=machinery_options.get("tags"),
            interface=machinery_options.get("interface"),
            snapshot=machinery_options.get("guest_snapshot"),  # TODO: this might be the image name?
            resultserver_ip=machinery_options.get("resultserver_ip"),
            resultserver_port=machinery_options.get("resultserver_port")
        )
        return

    def acquire(self, machine_id=None, platform=None, tags=None):
        """
        Override Machinery method to utilize the auto scale option
        as well as a FIFO queue for machines.
        @param machine_id: the name of the machine to be acquired
        @param platform: the platform of the machine's operating system
        @param tags: any tags that are associated with the machine
        """
        if self.machine_queue:
            # Used to minimize wait times as VMIs are starting up and some might
            # not ready to listen yet.
            machine_id = self.machine_queue.pop(0)
        base_class_return_value = super(KubeVirt, self).acquire(
            machine_id,
            platform,
            tags
        )
        self._create_and_start_machines()  # Prepare another machine
        return base_class_return_value

    def release(self, label=None):
        """
        Override abstract machinery method to have the ability to run
        _create_and_start_machines()
        after unlocking the last machine.
        @param label: machine label.
        """
        super(KubeVirt, self).release(label)
        self._create_and_start_machines()

    def _status(self, label):
        """
        Gets status of VMI
        @param label: virtual machine instance label.
        @return: VM state string.
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        try:
            vmi = self.api_client.read_namespaced_virtual_machine_instance(
                label,
                self.options.kubevirt.namespace
            )
        except ApiException as exc:
            log.error(
                "Exception when calling CoreV1Api->read_namespaced_" +
                "pod_status: '%s'.",
                exc
            )
            raise CuckooMachineError(exc)

        vmi_status = vmi.status
        phase = vmi_status.phase

        if phase == "Pending":
            vmi_phase = KubeVirt.PENDING
        elif phase == "Running":
            vmi_phase = KubeVirt.RUNNING
        elif phase == "Succeeded":
            vmi_phase = KubeVirt.SUCCEEDED
        elif phase == "Failed":
            vmi_phase = KubeVirt.FAILED
        elif phase == "Unknown":
            vmi_phase = KubeVirt.UNKNOWN
        else:
            vmi_phase = KubeVirt.ERROR
        return vmi_phase

    def stop(self, label=None):
        """
        Terminate VMI.
        @param label: virtual machine instance label
        @raise CuckooMachineError: if there is a problem with the KubeVirt call
        """
        log.debug("Stopping virtual machine instance '%s'.", label)
        self._delete_instance(label)

    def _list(self):
        """
        Retrieves all virtual machine instances in namespace.
        @return: A list of all instance names within namespace.
        @raise CuckooMachineError: if there is a problem with the KubeVirt call
        """
        try:
            log.debug("Retrieving all virtual machine instances in namespace.")
            instances = \
                self.api_instance.list_namespaced_virtual_machine_instance(
                    self.options.kubevirt.namespace
                )
        except ApiException as exc:
            log.error(
                "Exception when calling DefaultApi->list_namespaced_virtual_" +
                "machine_instance: '%s'.",
                exc
            )
            raise CuckooMachineError(exc)

        return [instance.name for instance in instances]

    def _delete_instance(self, instance_name):
        """
        Deletes an instance.
        @param instance_name: String indicating the name of the VMI to be
        deleted
        @return CuckooMachineError: if there is a problem with the KubeVirt call
        """
        try:
            log.info(
                "Terminating virtual machine instance '%s'.",
                instance_name
            )
            self.api_instance.delete_namespaced_virtual_machine_instance(
                kubevirt.V1DeleteOptions(),
                self.options.kubevirt.namespace,
                instance_name
            )
        except ApiException as exc:
            log.error(
                "Exception when calling DefaultApi->delete_namespaced_" +
                "virtual_machine: '%s'.",
                exc
            )
            raise CuckooMachineError(exc)

        # If the state of the system is past being initialized,
        # then delete the VMI entry from the DB.
        if not self.initializing:
            del self.kubevirt_machines[instance_name]
            self._delete_machine_from_db(instance_name)
            self.dynamic_machines_count -= 1


def read_yaml_file(path):
    """
    Cited from
    https://github.com/kubevirt/client-python/blob/master/examples/examplelib.py
    Read and parse YAML from given file.
    Args:
        path (str): Path to YAML file
    Returns:
        dict: content of file
    """
    import os
    import yaml
    path = os.path.join(os.path.dirname(__file__), path)
    with open(path) as fh:
        return yaml.load(fh)