use std::ffi::c_void;

use cuda_driver_sys::{CUdeviceptr, CUfunction, CUresult, CUstream};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ClusterDim {
    pub x: u32,
    pub y: u32,
    pub z: u32,
}

#[allow(non_snake_case)]
#[derive(Clone, Copy)]
#[repr(C)]
pub union CUlaunchAttributeValue {
    // accessPolicyWindow: CUaccessPolicyWindow,
    // cooperative: i32,
    // syncPolicy: CUsynchronizationPolicy,
    pub clusterDim: ClusterDim,
    // clusterSchedulingPolicyPreference: CUclusterSchedulingPolicy,
    // programmaticStreamSerializationAllowed: i32,
    // programmaticEvent: ProgrammaticEvent,
    // priority: i32,
    // memSyncDomainMap: CUlaunchMemSyncDomainMap,
    // memSyncDomain: CUlaunchMemSyncDomain,
    pub preferredClusterDim: ClusterDim,
    // launchCompletionEvent: LaunchCompletionEvent,
    // deviceUpdatableKernelNode: DeviceUpdatableKernelNode,
}

#[allow(non_camel_case_types, unused)]
#[repr(u32)]
pub enum CUlaunchAttributeID {
    CU_LAUNCH_ATTRIBUTE_IGNORE = 0,
    // CU_LAUNCH_ATTRIBUTE_ACCESS_POLICY_WINDOW   = 1,
    // CU_LAUNCH_ATTRIBUTE_COOPERATIVE            = 2,
    // CU_LAUNCH_ATTRIBUTE_SYNCHRONIZATION_POLICY = 3,
    CU_LAUNCH_ATTRIBUTE_CLUSTER_DIMENSION = 4,
    // CU_LAUNCH_ATTRIBUTE_CLUSTER_SCHEDULING_POLICY_PREFERENCE = 5,
    // CU_LAUNCH_ATTRIBUTE_PROGRAMMATIC_STREAM_SERIALIZATION    = 6,
    // CU_LAUNCH_ATTRIBUTE_PROGRAMMATIC_EVENT                   = 7,
    // CU_LAUNCH_ATTRIBUTE_PRIORITY               = 8,
    // CU_LAUNCH_ATTRIBUTE_MEM_SYNC_DOMAIN_MAP    = 9,
    // CU_LAUNCH_ATTRIBUTE_MEM_SYNC_DOMAIN        = 10,
    CU_LAUNCH_ATTRIBUTE_PREFERRED_CLUSTER_DIMENSION = 11,
    // CU_LAUNCH_ATTRIBUTE_LAUNCH_COMPLETION_EVENT = 12,
    // CU_LAUNCH_ATTRIBUTE_DEVICE_UPDATABLE_KERNEL_NODE = 13,
}

pub struct Padding<const N: usize>([u8; N]);

impl<const N: usize> Padding<N> {
    pub fn new() -> Self {
        Self([0u8; N])
    }
}

/// Launch attributes
///
/// # Remarks
/// From cuda.h
/// ```cpp
/// typedef struct CUlaunchAttribute_st {
///    CUlaunchAttributeID id; /**< Attribute to set */
///    char pad[8 - sizeof(CUlaunchAttributeID)];
///    CUlaunchAttributeValue value; /**< Value of the attribute */
/// } CUlaunchAttribute;
/// ```
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct CUlaunchAttribute {
    /// The type of attribute this is.
    pub id: CUlaunchAttributeID,
    /// Not sure why CUDA wants this, but it does.
    pub padding: Padding<{ 8 - std::mem::size_of::<CUlaunchAttributeID>() }>,
    /// The attribute value
    pub value: CUlaunchAttributeValue,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct CUlaunchConfig {
    pub gridDimX: u32,
    pub gridDimY: u32,
    pub gridDimZ: u32,
    pub blockDimX: u32,
    pub blockDimY: u32,
    pub blockDimZ: u32,
    pub sharedMemBytes: u32,
    pub hStream: CUstream,
    pub attrs: *mut CUlaunchAttribute,
    pub numAttrs: u32,
}

unsafe extern "C" {
    pub fn cuMemFreeAsync(ptr: CUdeviceptr, h_stream: CUstream) -> CUresult;

    pub fn cuLaunchKernelEx(
        config: *const CUlaunchConfig,
        f: CUfunction,
        args: *mut *mut c_void,
        extra: *mut c_void,
    ) -> CUresult;
}
