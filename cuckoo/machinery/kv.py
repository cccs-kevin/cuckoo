# Copyright (C) 2015-2021 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Contributed by the Canadian Centre for Cyber Security to support KubeVirt.

import logging
import os
import yaml
import threading
import time

try:
    # KubeVirt and Kubernetes-specific imports
    import kubevirt
    from kubernetes import config as k8s_config, client, watch
    HAVE_KV = True
except ImportError:
    HAVE_KV = False

# Cuckoo-specific imports
from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config as cuckoo_config
from cuckoo.common.exceptions import (
    CuckooCriticalError, CuckooMachineError, CuckooMachineSnapshotError,
    CuckooMissingMachineError, CuckooDependencyError, CuckooConfigurationError
)
log = logging.getLogger(__name__)


class KubeVirt(Machinery):
    """Virtualization layer for KubeVirt."""

    # Operating System Tag Prefixes
    WINDOWS_TAG_PREFIX = "win"
    LINUX_TAG_PREFIX = "ub"
    VALID_TAG_PREFIXES = [WINDOWS_TAG_PREFIX, LINUX_TAG_PREFIX]

    VM_NAME_FORMAT = "cuckoo-victim-%s-%s"

    # VM states
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    UNKNOWN = "Unknown"
    NONEXISTENT = "Nonexistent"
    STOPPED = "Stopped"

    def __init__(self):
        from cuckoo.misc import set_cwd
        set_cwd("/home/cuckoo/.cuckoo")
        from cuckoo.core.database import Database
        self.db = Database()
        self.db.connect()

        from cuckoo.common.config import Config
        self.set_options(Config("kv"))
        self.remote_control = False

    def _initialize(self, module_name):
        """
        Initializing instance parameters.
        @param module_name: module name
        """
        self.resource_type = None
        self.dynamic_machines_count = 0
        self.dynamic_machines_sequence = 0

        super(KubeVirt, self)._initialize(module_name)

    def _initialize_check(self):
        """Run all checks when a machine manager is initialized.
        @raise CuckooMachineError: if KubeVirt is not found.
        """
        if not HAVE_KV:
            raise CuckooDependencyError("Unable to import KubeVirt packages")
        if not self.options.kv.kubeconfig:
            raise CuckooCriticalError(
                "Kubernetes Configuration file path is missing, please add it to the "
                "kv.conf configuration file!"
            )

        if not os.path.exists(os.path.expanduser(self.options.kv.kubeconfig)):
            raise CuckooCriticalError(
                "Kubernetes Configuration not found at specified path \"%s\" "
                "(as specified in kv.conf). Did you properly install "
                "KubeVirt and configure Cuckoo to use it?"
                % self.options.kv.kubeconfig
            )
        # self.resource_type = "vm"
        super(KubeVirt, self)._initialize_check()

        log.info("Deleting leftover persistent volume claims and virtual machines.")
        # TODO: do the deleting of PVCs and VMs

        log.info("Reading the snapshot \"%s\" to be used to create victims." % self.options.kv.snapshots)
        # TODO: read the snapshot, get snapshot name, assign to class param and use it in create_machines

        # If the lengths are different, that means there isn't a 1:1 mapping of supported OS tags
        # and snapshots, when there should be.
        if len(self.options.kv.supported_os_tags) != len(self.options.kv.snapshots):
            raise CuckooConfigurationError(
                "The lengths of self.options.kv.supported_os_tags (%s) and "
                "self.options.kv.snapshots (%s) are not equal." % (
                    self.options.kv.supported_os_tags, self.options.kv.snapshots)
            )

        valid_vm_names = [KubeVirt.VM_NAME_FORMAT % (self.options.kv.environment, tag)
                          for tag in self.options.kv.supported_os_tags]

        self.required_vms = {vm_name: {} for vm_name in valid_vm_names}

        # Kubernetes API Client
        self._get_k8s_client()

        # KubeVirt API Client
        self._get_kv_client()

        self._set_vm_stage()

#        self._create_machines()

    def _set_vm_stage(self):
        """
        Ready. Set. Action! Set the stage for the VMs
        """
        # Check that each provided snapshot exists
        # custom_client = client.CustomObjectsApi(self.k8s_api)
        # snapshot = custom_client.get_namespaced_custom_object("snapshot.storage.k8s.io", "v1", self.options.kv.namespace, "volumesnapshots", "cuckoo-victim-win7x64-snapshot")

        # self.k8s_api.create_namespaced_persistent_volume_claim()
        for snapshot in self.options.kv.snapshots:
            # self._create_pvc(snapshot)
            self._create_machine(snapshot)


        pass


    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s", label)

        if self._status(label) == self.RUNNING:
            raise CuckooMachineError(
                "Trying to start an already started VM: %s" % label
            )

        machine = self.db.view_machine_by_label(label)
        self.restore(label, machine)

        self._wait_status(label, self.SAVED)

        try:
            # Start VM
            self.api.start(label, self.options.kv.namespace)
        except OSError as e:
            raise CuckooMachineError(
                "KubeVirt failed starting the machine. "
                "Are you sure your machine is still functioning correctly "
                "when trying to use it manually? Error: %s" % e
            )

        self._wait_status(label, self.RUNNING)

    def stop(self, label):
        """Stop a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vmi %s" % label)

        status = self._status(label)

        if status == self.NONEXISTENT:
            raise CuckooMachineError(
                "Trying to stop a VM that doesn't exist: %s" % label
            )
        if status == self.STOPPED:
            raise CuckooMachineError(
                "Trying to stop an already stopped VM: %s" % label
            )

        try:
            self.api.stop(label, NAMESPACE)
        except OSError as e:
            raise CuckooMachineError(
                "KubeVirt failed powering off the machine %s: %s" % (label, e)
            )

        self._wait_status(label, self.STOPPED, self.FAILED, self.UNKNOWN)


    def _list(self):
        """List resources installed.
        :param: resource type to be listed
        @return: resource names list.
        """
        resources = None
        if not self.resource_type:
            return []

        log.debug("Listing resources of type \"%s\"" % self.resource_type)

        if self.resource_type in ["vmi", "vmis"]:
            try:
                resources = self.kv_api.list_namespaced_virtual_machine_instance(NAMESPACE)
            except OSError as e:
                raise CuckooMachineError(
                    "KubeVirt Python Client error listing installed virtual machine instances: %s" % e
                )
        elif self.resource_type in ["vm", "vms"]:
            try:
                resources = self.kv_api.list_namespaced_virtual_machine(NAMESPACE)
            except OSError as e:
                raise CuckooMachineError(
                    "KubeVirt Python Client error listing installed virtual machines: %s" % e
                )
        labels = []
        if resources and resources.items:
            for item in resources.items:
                label = get_name(item)
                labels.append(label)
        return labels


    def _status(self, label):
        """Get current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        # First check if VM exists for label, and then we'll check for the VMI
        self.resource_type = "vm"
        if label not in self._list():
            # VM does not exist
            return self.NONEXISTENT
        self.resource_type = "vmi"
        if label not in self._list():
            # VM exists but VMI does not, which implies that the VMI is either
            # stopped or never turned on
            return self.STOPPED

        try:
            vmi = self.kv_api.read_namespaced_virtual_machine_instance(label, NAMESPACE)
        except OSError as e:
            raise CuckooMachineError(
                "KubeVirt Python Client error reading virtual machine instance %s: %s" % (label, e)
            )

        status = get_status(vmi)
        # Report back status.
        if status:
            self.set_status(label, status)
            return status
        else:
            raise CuckooMachineError(
                "Unable to get status for %s" % label
            )

    def _create_pvc(self, snapshot):
        tag = next(tag for tag in self.options.kv.supported_os_tags if tag in snapshot)
        pvc_name = "cuckoo-victim-%s-pvc" % tag
        #TODO: Add a tag here to be used to represent if can be deleted
        # Create PVC representing the Harddrive for the victim vm
        reqs = client.V1ResourceRequirements(requests={"storage": "15Gi"})
        spec = client.V1PersistentVolumeClaimSpec(resources=reqs, access_modes=["ReadWriteOnce"], data_source={"name": snapshot, "kind": "VolumeSnapshot", "apiGroup": "snapshot.storage.k8s.io"})
        body = client.V1PersistentVolumeClaim(api_version="v1", metadata={"name": pvc_name, "namespace": self.options.kv.namespace}, spec=spec)
        self.k8s_api.create_namespaced_persistent_volume_claim(namespace=self.options.kv.namespace, body=body)

    def _create_machines(self):
        available_machines = self.db.count_machines_available()
        running_machines_gap = self.options.kv.running_machines_gap
        dynamic_machines_limit = self.options.kv.dynamic_machines_limit

        #  If there are no available machines left  -> launch a new machine.
        threads = []
        while available_machines < running_machines_gap:
            # Sleeping for a couple because Rancher takes a while
            time.sleep(2)
            if self.dynamic_machines_count >= dynamic_machines_limit:
                log.debug(
                    "Reached dynamic machines limit - %d machines.",
                    dynamic_machines_limit
                )
                break
            else:
                # Using threads to create machines in parallel.
                self.dynamic_machines_count += 1
                thr = threading.Thread(target=self._create_machine)
                threads.append(thr)
                thr.start()
                available_machines += 1

    def _create_machine(self, snapshot):
        # TODO: use a tag here to mark if pvc/vm can be deleted
        # TODO: do something with snapshot in order to create pvc/vm
        # TODO: then get read vm to get all this info required below

        tag = next(tag for tag in self.options.kv.supported_os_tags if tag in snapshot)

        cpu = kubevirt.V1CPU(cores=2)
        virtio_disk_target = kubevirt.V1DiskTarget(bus="virtio")
        sata_cdrom_target = kubevirt.V1CDRomTarget(bus="sata")
        harddrive_disk = kubevirt.V1Disk(name="harddrive", disk=virtio_disk_target)
        virtiocontainerdisk = kubevirt.V1Disk(name="virtio", cdrom=sata_cdrom_target)
        devices = kubevirt.V1Devices(disks=[harddrive_disk, virtiocontainerdisk])
        machine = kubevirt.V1Machine(type="q35")
        resource_reqs = kubevirt.V1ResourceRequirements(requests={"memory": "200M"})
        domain_spec = kubevirt.V1DomainSpec(cpu=cpu, devices=devices, machine=machine, resources=resource_reqs)
        pvc = client.V1PersistentVolumeClaimSource(claimName="cuckoo-victim-win7x64-pvc")
        harddrive_volume = kubevirt.V1Volume(name="harddrive", persistentVolumeClaim=pvc)
        container_disk_source = kubevirt.V1ContainerDiskSource(image="kubevirt/virtio-container-disk")
        virtiocontainerdisk_volume = kubevirt.V1Volume(name="virtiocontainerdisk", containerDisk=container_disk_source)


        vmi_spec = kubevirt.V1VirtualMachineInstanceSpec(domain=domain_spec, volumes=[harddrive_volume, virtiocontainerdisk_volume])

        template = kubevirt.V1VirtualMachineInstanceTemplateSpec(spec=vmi_spec)
        vm_spec = kubevirt.V1VirtualMachineSpec(template=template)
        vm_body = kubevirt.V1VirtualMachine(kind="VirtualMachine", metadata={"name": "cuckoo-victim-win7x64-vm"}, spec=vm_spec)
        vm = {}
        try:
            log.debug("Creating virtual machine")
            vm = self.kv_api.create_namespaced_virtual_machine(body=vm_body, namespace=self.options.kv.namespace)
        except kubevirt.rest.ApiException as e:
            log.error("Exception when calling DefaultApi->create_namespaced_virtual_machine: %s\n" % e)

        vmi_body = kubevirt.V1VirtualMachineInstance()
        vmi = {}
        try:
            log.debug("Creating virtual machine instance")
            vmi = self.kv_api.create_namespaced_virtual_machine_instance(vmi_body, NAMESPACE)
        except kubevirt.rest.ApiException as e:
            log.error("Exception when calling DefaultApi->create_namespaced_virtual_machine_instance: %s\n" % e)

        name = get_name(vmi)

        # The ResultServer port might have been dynamically changed,
        # get it from the ResultServer singleton. Also avoid import
        # recursion issues by importing ResultServer here.
        from cuckoo.core.resultserver import ResultServer
        resultserver_port = ResultServer().port

        self.db.add_machine(
            name=name,
            label=name,
            ip=get_ip(vmi),
            platform=self.options.kv.platform,
            options="",
            tags="",
            interface=self.options.kv.interface,
            snapshot=self.options.kv.snapshot,
            resultserver_ip=cuckoo_config("cuckoo:resultserver:ip"),
            resultserver_port=resultserver_port
        )
        return

    def _get_kv_client(self):
        """
        This function loads kubeconfig and sets the KubeVirt API Client.
        """
        kubeconfig = os.path.expanduser(self.options.kv.kubeconfig)
        cl = k8s_config.kube_config._get_kube_config_loader_for_yaml_file(kubeconfig)
        cl.load_and_set(kubevirt.configuration)
        self.kv_api = kubevirt.DefaultApi()

    def _get_k8s_client(self):
        """
        This function loads kubeconfig and sets the Kubernetes API Client.
        """
        k8s_config.load_kube_config()
        self.k8s_api = client.CoreV1Api()


def read_yaml_file(path):
    """
    Read and parse YAML from given file.
    Args:
        path (str): Path to YAML file
    Returns:
        dict: content of file
    """
    path = os.path.join(os.path.dirname(__file__), path)
    with open(path) as fh:
        return yaml.load(fh)


def get_name(obj):
    if isinstance(obj, dict):
        return obj.get('metadata', dict()).get('name')
    return obj.metadata.name


def get_status(obj):
    if isinstance(obj, dict):
        return obj.get('status', dict()).get('phase')
    return obj.status.phase

def get_ip(obj):
    if isinstance(obj, dict):
        return obj.get('status', dict()).get('interfaces', list())[0].get('ip_address')
    return obj.status.interfaces[0].ip_address

def get_kv_client():
    """
    This function loads kubeconfig and sets the KubeVirt API Client.
    """
    kubeconfig = os.path.expanduser("~/.kube/config")
    cl = k8s_config.kube_config._get_kube_config_loader_for_yaml_file(kubeconfig)
    cl.load_and_set(kubevirt.configuration)
    return kubevirt.DefaultApi()

def main():
    kv = KubeVirt()
    kv.initialize("kv")
    kv._create_machine()

    # k8s_api = get_k8s_client()
    # # List existing VMs
    # vmis = kv_api.list_namespaced_virtual_machine_instance(NAMESPACE)
    # print(vmis)
    # List existing VMIs
    # vmis = api.list_namespaced_virtual_machine_instance(NAMESPACE)
    # for vmi in _list(api):
    #     status = _status(api, vmi)
    #     print(status)
    # start(api, "cuckoo-victim-vm")
    # Create Snapshot metadata={"name": "cuckoo-victim-vm-snapshot"},
    # body = kubevirt.V1alpha1VirtualMachineSnapshot(api_version="snapshot.kubevirt.io/v1alpha1", kind="VirtualMachineSnapshot", metadata={"name": "cuckoo-victim-snapshot"}, spec={"source": {"api_group": "kubevirt.io", "kind": "VirtualMachine", "name": "cuckoo-victim-vm"}})
    # kv_api.create_namespaced_virtual_machine_snapshot(body, NAMESPACE)
    # Create Virtual Machine Instance
    # cpu = kubevirt.V1CPU(cores=2)
    # disk_target = kubevirt.V1DiskTarget(bus="virtio")
    # disk = kubevirt.V1Disk(disk=disk_target, name="harddrive")
    # interface = kubevirt.V1Interface(bridge={}, name="default")
    # devices = kubevirt.V1Devices(disks=[disk], interfaces=[interface])
    # feature_state = kubevirt.V1FeatureState(enabled=True)
    # features = kubevirt.V1Features(acpi=feature_state)
    # firmware = kubevirt.V1Firmware(uuid="f7d4196c-3934-5975-a69e-dabb67017a4e")
    # machine = kubevirt.V1Machine(type="q35")
    # resource_reqs = kubevirt.V1ResourceRequirements(
    #     limits={"cpu":2, "memory":"2Gi"},
    #     requests={"cpu":2, "memory":"200M"}
    # )
    #
    # volume = kubevirt.V1Volume(name="harddrive", )
    # domain = kubevirt.V1DomainSpec(
    #     cpu=cpu,
    #     devices=devices,
    #     features=features,
    #     firmware=firmware,
    #     machine=machine,
    #     resources=resource_reqs,
    #
    # )
    # spec = kubevirt.V1VirtualMachineInstanceSpec()
    # body = kubevirt.V1VirtualMachineInstance(spec=spec)
    # kv_api.create_namespaced_virtual_machine_instance(body, NAMESPACE)


if __name__ == "__main__":
    main()