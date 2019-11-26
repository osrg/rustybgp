// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

const METHOD_GOBGP_API_START_BGP: ::grpcio::Method<super::gobgp::StartBgpRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/StartBgp",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_STOP_BGP: ::grpcio::Method<super::gobgp::StopBgpRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/StopBgp",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_GET_BGP: ::grpcio::Method<super::gobgp::GetBgpRequest, super::gobgp::GetBgpResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/GetBgp",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_PEER: ::grpcio::Method<super::gobgp::AddPeerRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddPeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_PEER: ::grpcio::Method<super::gobgp::DeletePeerRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeletePeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_PEER: ::grpcio::Method<super::gobgp::ListPeerRequest, super::gobgp::ListPeerResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListPeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_UPDATE_PEER: ::grpcio::Method<super::gobgp::UpdatePeerRequest, super::gobgp::UpdatePeerResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/UpdatePeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_RESET_PEER: ::grpcio::Method<super::gobgp::ResetPeerRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/ResetPeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_SHUTDOWN_PEER: ::grpcio::Method<super::gobgp::ShutdownPeerRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/ShutdownPeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ENABLE_PEER: ::grpcio::Method<super::gobgp::EnablePeerRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/EnablePeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DISABLE_PEER: ::grpcio::Method<super::gobgp::DisablePeerRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DisablePeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_MONITOR_PEER: ::grpcio::Method<super::gobgp::MonitorPeerRequest, super::gobgp::MonitorPeerResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/MonitorPeer",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_PEER_GROUP: ::grpcio::Method<super::gobgp::AddPeerGroupRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddPeerGroup",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_PEER_GROUP: ::grpcio::Method<super::gobgp::DeletePeerGroupRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeletePeerGroup",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_UPDATE_PEER_GROUP: ::grpcio::Method<super::gobgp::UpdatePeerGroupRequest, super::gobgp::UpdatePeerGroupResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/UpdatePeerGroup",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_DYNAMIC_NEIGHBOR: ::grpcio::Method<super::gobgp::AddDynamicNeighborRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddDynamicNeighbor",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_PATH: ::grpcio::Method<super::gobgp::AddPathRequest, super::gobgp::AddPathResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddPath",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_PATH: ::grpcio::Method<super::gobgp::DeletePathRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeletePath",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_PATH: ::grpcio::Method<super::gobgp::ListPathRequest, super::gobgp::ListPathResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListPath",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_PATH_STREAM: ::grpcio::Method<super::gobgp::AddPathStreamRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ClientStreaming,
    name: "/gobgpapi.GobgpApi/AddPathStream",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_GET_TABLE: ::grpcio::Method<super::gobgp::GetTableRequest, super::gobgp::GetTableResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/GetTable",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_MONITOR_TABLE: ::grpcio::Method<super::gobgp::MonitorTableRequest, super::gobgp::MonitorTableResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/MonitorTable",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_VRF: ::grpcio::Method<super::gobgp::AddVrfRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddVrf",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_VRF: ::grpcio::Method<super::gobgp::DeleteVrfRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeleteVrf",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_VRF: ::grpcio::Method<super::gobgp::ListVrfRequest, super::gobgp::ListVrfResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListVrf",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_POLICY: ::grpcio::Method<super::gobgp::AddPolicyRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddPolicy",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_POLICY: ::grpcio::Method<super::gobgp::DeletePolicyRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeletePolicy",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_POLICY: ::grpcio::Method<super::gobgp::ListPolicyRequest, super::gobgp::ListPolicyResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListPolicy",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_SET_POLICIES: ::grpcio::Method<super::gobgp::SetPoliciesRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/SetPolicies",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_DEFINED_SET: ::grpcio::Method<super::gobgp::AddDefinedSetRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddDefinedSet",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_DEFINED_SET: ::grpcio::Method<super::gobgp::DeleteDefinedSetRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeleteDefinedSet",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_DEFINED_SET: ::grpcio::Method<super::gobgp::ListDefinedSetRequest, super::gobgp::ListDefinedSetResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListDefinedSet",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_STATEMENT: ::grpcio::Method<super::gobgp::AddStatementRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddStatement",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_STATEMENT: ::grpcio::Method<super::gobgp::DeleteStatementRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeleteStatement",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_STATEMENT: ::grpcio::Method<super::gobgp::ListStatementRequest, super::gobgp::ListStatementResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListStatement",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_POLICY_ASSIGNMENT: ::grpcio::Method<super::gobgp::AddPolicyAssignmentRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddPolicyAssignment",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_POLICY_ASSIGNMENT: ::grpcio::Method<super::gobgp::DeletePolicyAssignmentRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeletePolicyAssignment",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_POLICY_ASSIGNMENT: ::grpcio::Method<super::gobgp::ListPolicyAssignmentRequest, super::gobgp::ListPolicyAssignmentResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListPolicyAssignment",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_SET_POLICY_ASSIGNMENT: ::grpcio::Method<super::gobgp::SetPolicyAssignmentRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/SetPolicyAssignment",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_RPKI: ::grpcio::Method<super::gobgp::AddRpkiRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddRpki",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_RPKI: ::grpcio::Method<super::gobgp::DeleteRpkiRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeleteRpki",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_RPKI: ::grpcio::Method<super::gobgp::ListRpkiRequest, super::gobgp::ListRpkiResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListRpki",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ENABLE_RPKI: ::grpcio::Method<super::gobgp::EnableRpkiRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/EnableRpki",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DISABLE_RPKI: ::grpcio::Method<super::gobgp::DisableRpkiRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DisableRpki",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_RESET_RPKI: ::grpcio::Method<super::gobgp::ResetRpkiRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/ResetRpki",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_LIST_RPKI_TABLE: ::grpcio::Method<super::gobgp::ListRpkiTableRequest, super::gobgp::ListRpkiTableResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/gobgpapi.GobgpApi/ListRpkiTable",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ENABLE_ZEBRA: ::grpcio::Method<super::gobgp::EnableZebraRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/EnableZebra",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ENABLE_MRT: ::grpcio::Method<super::gobgp::EnableMrtRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/EnableMrt",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DISABLE_MRT: ::grpcio::Method<super::gobgp::DisableMrtRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DisableMrt",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_ADD_BMP: ::grpcio::Method<super::gobgp::AddBmpRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/AddBmp",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_GOBGP_API_DELETE_BMP: ::grpcio::Method<super::gobgp::DeleteBmpRequest, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/gobgpapi.GobgpApi/DeleteBmp",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

#[derive(Clone)]
pub struct GobgpApiClient {
    client: ::grpcio::Client,
}

impl GobgpApiClient {
    pub fn new(channel: ::grpcio::Channel) -> Self {
        GobgpApiClient {
            client: ::grpcio::Client::new(channel),
        }
    }

    pub fn start_bgp_opt(&self, req: &super::gobgp::StartBgpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_START_BGP, req, opt)
    }

    pub fn start_bgp(&self, req: &super::gobgp::StartBgpRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.start_bgp_opt(req, ::grpcio::CallOption::default())
    }

    pub fn start_bgp_async_opt(&self, req: &super::gobgp::StartBgpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_START_BGP, req, opt)
    }

    pub fn start_bgp_async(&self, req: &super::gobgp::StartBgpRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.start_bgp_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn stop_bgp_opt(&self, req: &super::gobgp::StopBgpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_STOP_BGP, req, opt)
    }

    pub fn stop_bgp(&self, req: &super::gobgp::StopBgpRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.stop_bgp_opt(req, ::grpcio::CallOption::default())
    }

    pub fn stop_bgp_async_opt(&self, req: &super::gobgp::StopBgpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_STOP_BGP, req, opt)
    }

    pub fn stop_bgp_async(&self, req: &super::gobgp::StopBgpRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.stop_bgp_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn get_bgp_opt(&self, req: &super::gobgp::GetBgpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::gobgp::GetBgpResponse> {
        self.client.unary_call(&METHOD_GOBGP_API_GET_BGP, req, opt)
    }

    pub fn get_bgp(&self, req: &super::gobgp::GetBgpRequest) -> ::grpcio::Result<super::gobgp::GetBgpResponse> {
        self.get_bgp_opt(req, ::grpcio::CallOption::default())
    }

    pub fn get_bgp_async_opt(&self, req: &super::gobgp::GetBgpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::GetBgpResponse>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_GET_BGP, req, opt)
    }

    pub fn get_bgp_async(&self, req: &super::gobgp::GetBgpRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::GetBgpResponse>> {
        self.get_bgp_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_peer_opt(&self, req: &super::gobgp::AddPeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_PEER, req, opt)
    }

    pub fn add_peer(&self, req: &super::gobgp::AddPeerRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_peer_async_opt(&self, req: &super::gobgp::AddPeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_PEER, req, opt)
    }

    pub fn add_peer_async(&self, req: &super::gobgp::AddPeerRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_peer_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_peer_opt(&self, req: &super::gobgp::DeletePeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_PEER, req, opt)
    }

    pub fn delete_peer(&self, req: &super::gobgp::DeletePeerRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_peer_async_opt(&self, req: &super::gobgp::DeletePeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_PEER, req, opt)
    }

    pub fn delete_peer_async(&self, req: &super::gobgp::DeletePeerRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_peer_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_peer_opt(&self, req: &super::gobgp::ListPeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListPeerResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_PEER, req, opt)
    }

    pub fn list_peer(&self, req: &super::gobgp::ListPeerRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListPeerResponse>> {
        self.list_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn update_peer_opt(&self, req: &super::gobgp::UpdatePeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::gobgp::UpdatePeerResponse> {
        self.client.unary_call(&METHOD_GOBGP_API_UPDATE_PEER, req, opt)
    }

    pub fn update_peer(&self, req: &super::gobgp::UpdatePeerRequest) -> ::grpcio::Result<super::gobgp::UpdatePeerResponse> {
        self.update_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn update_peer_async_opt(&self, req: &super::gobgp::UpdatePeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::UpdatePeerResponse>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_UPDATE_PEER, req, opt)
    }

    pub fn update_peer_async(&self, req: &super::gobgp::UpdatePeerRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::UpdatePeerResponse>> {
        self.update_peer_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn reset_peer_opt(&self, req: &super::gobgp::ResetPeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_RESET_PEER, req, opt)
    }

    pub fn reset_peer(&self, req: &super::gobgp::ResetPeerRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.reset_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn reset_peer_async_opt(&self, req: &super::gobgp::ResetPeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_RESET_PEER, req, opt)
    }

    pub fn reset_peer_async(&self, req: &super::gobgp::ResetPeerRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.reset_peer_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn shutdown_peer_opt(&self, req: &super::gobgp::ShutdownPeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_SHUTDOWN_PEER, req, opt)
    }

    pub fn shutdown_peer(&self, req: &super::gobgp::ShutdownPeerRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.shutdown_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn shutdown_peer_async_opt(&self, req: &super::gobgp::ShutdownPeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_SHUTDOWN_PEER, req, opt)
    }

    pub fn shutdown_peer_async(&self, req: &super::gobgp::ShutdownPeerRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.shutdown_peer_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enable_peer_opt(&self, req: &super::gobgp::EnablePeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ENABLE_PEER, req, opt)
    }

    pub fn enable_peer(&self, req: &super::gobgp::EnablePeerRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.enable_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enable_peer_async_opt(&self, req: &super::gobgp::EnablePeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ENABLE_PEER, req, opt)
    }

    pub fn enable_peer_async(&self, req: &super::gobgp::EnablePeerRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.enable_peer_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn disable_peer_opt(&self, req: &super::gobgp::DisablePeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DISABLE_PEER, req, opt)
    }

    pub fn disable_peer(&self, req: &super::gobgp::DisablePeerRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.disable_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn disable_peer_async_opt(&self, req: &super::gobgp::DisablePeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DISABLE_PEER, req, opt)
    }

    pub fn disable_peer_async(&self, req: &super::gobgp::DisablePeerRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.disable_peer_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn monitor_peer_opt(&self, req: &super::gobgp::MonitorPeerRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::MonitorPeerResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_MONITOR_PEER, req, opt)
    }

    pub fn monitor_peer(&self, req: &super::gobgp::MonitorPeerRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::MonitorPeerResponse>> {
        self.monitor_peer_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_peer_group_opt(&self, req: &super::gobgp::AddPeerGroupRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_PEER_GROUP, req, opt)
    }

    pub fn add_peer_group(&self, req: &super::gobgp::AddPeerGroupRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_peer_group_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_peer_group_async_opt(&self, req: &super::gobgp::AddPeerGroupRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_PEER_GROUP, req, opt)
    }

    pub fn add_peer_group_async(&self, req: &super::gobgp::AddPeerGroupRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_peer_group_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_peer_group_opt(&self, req: &super::gobgp::DeletePeerGroupRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_PEER_GROUP, req, opt)
    }

    pub fn delete_peer_group(&self, req: &super::gobgp::DeletePeerGroupRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_peer_group_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_peer_group_async_opt(&self, req: &super::gobgp::DeletePeerGroupRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_PEER_GROUP, req, opt)
    }

    pub fn delete_peer_group_async(&self, req: &super::gobgp::DeletePeerGroupRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_peer_group_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn update_peer_group_opt(&self, req: &super::gobgp::UpdatePeerGroupRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::gobgp::UpdatePeerGroupResponse> {
        self.client.unary_call(&METHOD_GOBGP_API_UPDATE_PEER_GROUP, req, opt)
    }

    pub fn update_peer_group(&self, req: &super::gobgp::UpdatePeerGroupRequest) -> ::grpcio::Result<super::gobgp::UpdatePeerGroupResponse> {
        self.update_peer_group_opt(req, ::grpcio::CallOption::default())
    }

    pub fn update_peer_group_async_opt(&self, req: &super::gobgp::UpdatePeerGroupRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::UpdatePeerGroupResponse>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_UPDATE_PEER_GROUP, req, opt)
    }

    pub fn update_peer_group_async(&self, req: &super::gobgp::UpdatePeerGroupRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::UpdatePeerGroupResponse>> {
        self.update_peer_group_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_dynamic_neighbor_opt(&self, req: &super::gobgp::AddDynamicNeighborRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_DYNAMIC_NEIGHBOR, req, opt)
    }

    pub fn add_dynamic_neighbor(&self, req: &super::gobgp::AddDynamicNeighborRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_dynamic_neighbor_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_dynamic_neighbor_async_opt(&self, req: &super::gobgp::AddDynamicNeighborRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_DYNAMIC_NEIGHBOR, req, opt)
    }

    pub fn add_dynamic_neighbor_async(&self, req: &super::gobgp::AddDynamicNeighborRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_dynamic_neighbor_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_path_opt(&self, req: &super::gobgp::AddPathRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::gobgp::AddPathResponse> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_PATH, req, opt)
    }

    pub fn add_path(&self, req: &super::gobgp::AddPathRequest) -> ::grpcio::Result<super::gobgp::AddPathResponse> {
        self.add_path_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_path_async_opt(&self, req: &super::gobgp::AddPathRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::AddPathResponse>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_PATH, req, opt)
    }

    pub fn add_path_async(&self, req: &super::gobgp::AddPathRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::AddPathResponse>> {
        self.add_path_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_path_opt(&self, req: &super::gobgp::DeletePathRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_PATH, req, opt)
    }

    pub fn delete_path(&self, req: &super::gobgp::DeletePathRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_path_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_path_async_opt(&self, req: &super::gobgp::DeletePathRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_PATH, req, opt)
    }

    pub fn delete_path_async(&self, req: &super::gobgp::DeletePathRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_path_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_path_opt(&self, req: &super::gobgp::ListPathRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListPathResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_PATH, req, opt)
    }

    pub fn list_path(&self, req: &super::gobgp::ListPathRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListPathResponse>> {
        self.list_path_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_path_stream_opt(&self, opt: ::grpcio::CallOption) -> ::grpcio::Result<(::grpcio::ClientCStreamSender<super::gobgp::AddPathStreamRequest>, ::grpcio::ClientCStreamReceiver<super::empty::Empty>)> {
        self.client.client_streaming(&METHOD_GOBGP_API_ADD_PATH_STREAM, opt)
    }

    pub fn add_path_stream(&self) -> ::grpcio::Result<(::grpcio::ClientCStreamSender<super::gobgp::AddPathStreamRequest>, ::grpcio::ClientCStreamReceiver<super::empty::Empty>)> {
        self.add_path_stream_opt(::grpcio::CallOption::default())
    }

    pub fn get_table_opt(&self, req: &super::gobgp::GetTableRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::gobgp::GetTableResponse> {
        self.client.unary_call(&METHOD_GOBGP_API_GET_TABLE, req, opt)
    }

    pub fn get_table(&self, req: &super::gobgp::GetTableRequest) -> ::grpcio::Result<super::gobgp::GetTableResponse> {
        self.get_table_opt(req, ::grpcio::CallOption::default())
    }

    pub fn get_table_async_opt(&self, req: &super::gobgp::GetTableRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::GetTableResponse>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_GET_TABLE, req, opt)
    }

    pub fn get_table_async(&self, req: &super::gobgp::GetTableRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::gobgp::GetTableResponse>> {
        self.get_table_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn monitor_table_opt(&self, req: &super::gobgp::MonitorTableRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::MonitorTableResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_MONITOR_TABLE, req, opt)
    }

    pub fn monitor_table(&self, req: &super::gobgp::MonitorTableRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::MonitorTableResponse>> {
        self.monitor_table_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_vrf_opt(&self, req: &super::gobgp::AddVrfRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_VRF, req, opt)
    }

    pub fn add_vrf(&self, req: &super::gobgp::AddVrfRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_vrf_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_vrf_async_opt(&self, req: &super::gobgp::AddVrfRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_VRF, req, opt)
    }

    pub fn add_vrf_async(&self, req: &super::gobgp::AddVrfRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_vrf_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_vrf_opt(&self, req: &super::gobgp::DeleteVrfRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_VRF, req, opt)
    }

    pub fn delete_vrf(&self, req: &super::gobgp::DeleteVrfRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_vrf_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_vrf_async_opt(&self, req: &super::gobgp::DeleteVrfRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_VRF, req, opt)
    }

    pub fn delete_vrf_async(&self, req: &super::gobgp::DeleteVrfRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_vrf_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_vrf_opt(&self, req: &super::gobgp::ListVrfRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListVrfResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_VRF, req, opt)
    }

    pub fn list_vrf(&self, req: &super::gobgp::ListVrfRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListVrfResponse>> {
        self.list_vrf_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_policy_opt(&self, req: &super::gobgp::AddPolicyRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_POLICY, req, opt)
    }

    pub fn add_policy(&self, req: &super::gobgp::AddPolicyRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_policy_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_policy_async_opt(&self, req: &super::gobgp::AddPolicyRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_POLICY, req, opt)
    }

    pub fn add_policy_async(&self, req: &super::gobgp::AddPolicyRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_policy_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_policy_opt(&self, req: &super::gobgp::DeletePolicyRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_POLICY, req, opt)
    }

    pub fn delete_policy(&self, req: &super::gobgp::DeletePolicyRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_policy_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_policy_async_opt(&self, req: &super::gobgp::DeletePolicyRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_POLICY, req, opt)
    }

    pub fn delete_policy_async(&self, req: &super::gobgp::DeletePolicyRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_policy_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_policy_opt(&self, req: &super::gobgp::ListPolicyRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListPolicyResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_POLICY, req, opt)
    }

    pub fn list_policy(&self, req: &super::gobgp::ListPolicyRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListPolicyResponse>> {
        self.list_policy_opt(req, ::grpcio::CallOption::default())
    }

    pub fn set_policies_opt(&self, req: &super::gobgp::SetPoliciesRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_SET_POLICIES, req, opt)
    }

    pub fn set_policies(&self, req: &super::gobgp::SetPoliciesRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.set_policies_opt(req, ::grpcio::CallOption::default())
    }

    pub fn set_policies_async_opt(&self, req: &super::gobgp::SetPoliciesRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_SET_POLICIES, req, opt)
    }

    pub fn set_policies_async(&self, req: &super::gobgp::SetPoliciesRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.set_policies_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_defined_set_opt(&self, req: &super::gobgp::AddDefinedSetRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_DEFINED_SET, req, opt)
    }

    pub fn add_defined_set(&self, req: &super::gobgp::AddDefinedSetRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_defined_set_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_defined_set_async_opt(&self, req: &super::gobgp::AddDefinedSetRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_DEFINED_SET, req, opt)
    }

    pub fn add_defined_set_async(&self, req: &super::gobgp::AddDefinedSetRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_defined_set_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_defined_set_opt(&self, req: &super::gobgp::DeleteDefinedSetRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_DEFINED_SET, req, opt)
    }

    pub fn delete_defined_set(&self, req: &super::gobgp::DeleteDefinedSetRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_defined_set_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_defined_set_async_opt(&self, req: &super::gobgp::DeleteDefinedSetRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_DEFINED_SET, req, opt)
    }

    pub fn delete_defined_set_async(&self, req: &super::gobgp::DeleteDefinedSetRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_defined_set_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_defined_set_opt(&self, req: &super::gobgp::ListDefinedSetRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListDefinedSetResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_DEFINED_SET, req, opt)
    }

    pub fn list_defined_set(&self, req: &super::gobgp::ListDefinedSetRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListDefinedSetResponse>> {
        self.list_defined_set_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_statement_opt(&self, req: &super::gobgp::AddStatementRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_STATEMENT, req, opt)
    }

    pub fn add_statement(&self, req: &super::gobgp::AddStatementRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_statement_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_statement_async_opt(&self, req: &super::gobgp::AddStatementRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_STATEMENT, req, opt)
    }

    pub fn add_statement_async(&self, req: &super::gobgp::AddStatementRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_statement_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_statement_opt(&self, req: &super::gobgp::DeleteStatementRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_STATEMENT, req, opt)
    }

    pub fn delete_statement(&self, req: &super::gobgp::DeleteStatementRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_statement_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_statement_async_opt(&self, req: &super::gobgp::DeleteStatementRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_STATEMENT, req, opt)
    }

    pub fn delete_statement_async(&self, req: &super::gobgp::DeleteStatementRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_statement_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_statement_opt(&self, req: &super::gobgp::ListStatementRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListStatementResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_STATEMENT, req, opt)
    }

    pub fn list_statement(&self, req: &super::gobgp::ListStatementRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListStatementResponse>> {
        self.list_statement_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_policy_assignment_opt(&self, req: &super::gobgp::AddPolicyAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_POLICY_ASSIGNMENT, req, opt)
    }

    pub fn add_policy_assignment(&self, req: &super::gobgp::AddPolicyAssignmentRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_policy_assignment_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_policy_assignment_async_opt(&self, req: &super::gobgp::AddPolicyAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_POLICY_ASSIGNMENT, req, opt)
    }

    pub fn add_policy_assignment_async(&self, req: &super::gobgp::AddPolicyAssignmentRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_policy_assignment_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_policy_assignment_opt(&self, req: &super::gobgp::DeletePolicyAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_POLICY_ASSIGNMENT, req, opt)
    }

    pub fn delete_policy_assignment(&self, req: &super::gobgp::DeletePolicyAssignmentRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_policy_assignment_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_policy_assignment_async_opt(&self, req: &super::gobgp::DeletePolicyAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_POLICY_ASSIGNMENT, req, opt)
    }

    pub fn delete_policy_assignment_async(&self, req: &super::gobgp::DeletePolicyAssignmentRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_policy_assignment_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_policy_assignment_opt(&self, req: &super::gobgp::ListPolicyAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListPolicyAssignmentResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_POLICY_ASSIGNMENT, req, opt)
    }

    pub fn list_policy_assignment(&self, req: &super::gobgp::ListPolicyAssignmentRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListPolicyAssignmentResponse>> {
        self.list_policy_assignment_opt(req, ::grpcio::CallOption::default())
    }

    pub fn set_policy_assignment_opt(&self, req: &super::gobgp::SetPolicyAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_SET_POLICY_ASSIGNMENT, req, opt)
    }

    pub fn set_policy_assignment(&self, req: &super::gobgp::SetPolicyAssignmentRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.set_policy_assignment_opt(req, ::grpcio::CallOption::default())
    }

    pub fn set_policy_assignment_async_opt(&self, req: &super::gobgp::SetPolicyAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_SET_POLICY_ASSIGNMENT, req, opt)
    }

    pub fn set_policy_assignment_async(&self, req: &super::gobgp::SetPolicyAssignmentRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.set_policy_assignment_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_rpki_opt(&self, req: &super::gobgp::AddRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_RPKI, req, opt)
    }

    pub fn add_rpki(&self, req: &super::gobgp::AddRpkiRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_rpki_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_rpki_async_opt(&self, req: &super::gobgp::AddRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_RPKI, req, opt)
    }

    pub fn add_rpki_async(&self, req: &super::gobgp::AddRpkiRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_rpki_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_rpki_opt(&self, req: &super::gobgp::DeleteRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_RPKI, req, opt)
    }

    pub fn delete_rpki(&self, req: &super::gobgp::DeleteRpkiRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_rpki_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_rpki_async_opt(&self, req: &super::gobgp::DeleteRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_RPKI, req, opt)
    }

    pub fn delete_rpki_async(&self, req: &super::gobgp::DeleteRpkiRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_rpki_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_rpki_opt(&self, req: &super::gobgp::ListRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListRpkiResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_RPKI, req, opt)
    }

    pub fn list_rpki(&self, req: &super::gobgp::ListRpkiRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListRpkiResponse>> {
        self.list_rpki_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enable_rpki_opt(&self, req: &super::gobgp::EnableRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ENABLE_RPKI, req, opt)
    }

    pub fn enable_rpki(&self, req: &super::gobgp::EnableRpkiRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.enable_rpki_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enable_rpki_async_opt(&self, req: &super::gobgp::EnableRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ENABLE_RPKI, req, opt)
    }

    pub fn enable_rpki_async(&self, req: &super::gobgp::EnableRpkiRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.enable_rpki_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn disable_rpki_opt(&self, req: &super::gobgp::DisableRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DISABLE_RPKI, req, opt)
    }

    pub fn disable_rpki(&self, req: &super::gobgp::DisableRpkiRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.disable_rpki_opt(req, ::grpcio::CallOption::default())
    }

    pub fn disable_rpki_async_opt(&self, req: &super::gobgp::DisableRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DISABLE_RPKI, req, opt)
    }

    pub fn disable_rpki_async(&self, req: &super::gobgp::DisableRpkiRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.disable_rpki_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn reset_rpki_opt(&self, req: &super::gobgp::ResetRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_RESET_RPKI, req, opt)
    }

    pub fn reset_rpki(&self, req: &super::gobgp::ResetRpkiRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.reset_rpki_opt(req, ::grpcio::CallOption::default())
    }

    pub fn reset_rpki_async_opt(&self, req: &super::gobgp::ResetRpkiRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_RESET_RPKI, req, opt)
    }

    pub fn reset_rpki_async(&self, req: &super::gobgp::ResetRpkiRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.reset_rpki_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn list_rpki_table_opt(&self, req: &super::gobgp::ListRpkiTableRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListRpkiTableResponse>> {
        self.client.server_streaming(&METHOD_GOBGP_API_LIST_RPKI_TABLE, req, opt)
    }

    pub fn list_rpki_table(&self, req: &super::gobgp::ListRpkiTableRequest) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::gobgp::ListRpkiTableResponse>> {
        self.list_rpki_table_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enable_zebra_opt(&self, req: &super::gobgp::EnableZebraRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ENABLE_ZEBRA, req, opt)
    }

    pub fn enable_zebra(&self, req: &super::gobgp::EnableZebraRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.enable_zebra_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enable_zebra_async_opt(&self, req: &super::gobgp::EnableZebraRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ENABLE_ZEBRA, req, opt)
    }

    pub fn enable_zebra_async(&self, req: &super::gobgp::EnableZebraRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.enable_zebra_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enable_mrt_opt(&self, req: &super::gobgp::EnableMrtRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ENABLE_MRT, req, opt)
    }

    pub fn enable_mrt(&self, req: &super::gobgp::EnableMrtRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.enable_mrt_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enable_mrt_async_opt(&self, req: &super::gobgp::EnableMrtRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ENABLE_MRT, req, opt)
    }

    pub fn enable_mrt_async(&self, req: &super::gobgp::EnableMrtRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.enable_mrt_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn disable_mrt_opt(&self, req: &super::gobgp::DisableMrtRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DISABLE_MRT, req, opt)
    }

    pub fn disable_mrt(&self, req: &super::gobgp::DisableMrtRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.disable_mrt_opt(req, ::grpcio::CallOption::default())
    }

    pub fn disable_mrt_async_opt(&self, req: &super::gobgp::DisableMrtRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DISABLE_MRT, req, opt)
    }

    pub fn disable_mrt_async(&self, req: &super::gobgp::DisableMrtRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.disable_mrt_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_bmp_opt(&self, req: &super::gobgp::AddBmpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_ADD_BMP, req, opt)
    }

    pub fn add_bmp(&self, req: &super::gobgp::AddBmpRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.add_bmp_opt(req, ::grpcio::CallOption::default())
    }

    pub fn add_bmp_async_opt(&self, req: &super::gobgp::AddBmpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_ADD_BMP, req, opt)
    }

    pub fn add_bmp_async(&self, req: &super::gobgp::AddBmpRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.add_bmp_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_bmp_opt(&self, req: &super::gobgp::DeleteBmpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_GOBGP_API_DELETE_BMP, req, opt)
    }

    pub fn delete_bmp(&self, req: &super::gobgp::DeleteBmpRequest) -> ::grpcio::Result<super::empty::Empty> {
        self.delete_bmp_opt(req, ::grpcio::CallOption::default())
    }

    pub fn delete_bmp_async_opt(&self, req: &super::gobgp::DeleteBmpRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_GOBGP_API_DELETE_BMP, req, opt)
    }

    pub fn delete_bmp_async(&self, req: &super::gobgp::DeleteBmpRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.delete_bmp_async_opt(req, ::grpcio::CallOption::default())
    }
    pub fn spawn<F>(&self, f: F) where F: ::futures::Future<Item = (), Error = ()> + Send + 'static {
        self.client.spawn(f)
    }
}

pub trait GobgpApi {
    fn start_bgp(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::StartBgpRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn stop_bgp(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::StopBgpRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn get_bgp(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::GetBgpRequest, sink: ::grpcio::UnarySink<super::gobgp::GetBgpResponse>);
    fn add_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddPeerRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeletePeerRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListPeerRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListPeerResponse>);
    fn update_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::UpdatePeerRequest, sink: ::grpcio::UnarySink<super::gobgp::UpdatePeerResponse>);
    fn reset_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ResetPeerRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn shutdown_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ShutdownPeerRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn enable_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::EnablePeerRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn disable_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DisablePeerRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn monitor_peer(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::MonitorPeerRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::MonitorPeerResponse>);
    fn add_peer_group(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddPeerGroupRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_peer_group(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeletePeerGroupRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn update_peer_group(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::UpdatePeerGroupRequest, sink: ::grpcio::UnarySink<super::gobgp::UpdatePeerGroupResponse>);
    fn add_dynamic_neighbor(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddDynamicNeighborRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn add_path(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddPathRequest, sink: ::grpcio::UnarySink<super::gobgp::AddPathResponse>);
    fn delete_path(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeletePathRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_path(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListPathRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListPathResponse>);
    fn add_path_stream(&mut self, ctx: ::grpcio::RpcContext, stream: ::grpcio::RequestStream<super::gobgp::AddPathStreamRequest>, sink: ::grpcio::ClientStreamingSink<super::empty::Empty>);
    fn get_table(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::GetTableRequest, sink: ::grpcio::UnarySink<super::gobgp::GetTableResponse>);
    fn monitor_table(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::MonitorTableRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::MonitorTableResponse>);
    fn add_vrf(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddVrfRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_vrf(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeleteVrfRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_vrf(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListVrfRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListVrfResponse>);
    fn add_policy(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddPolicyRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_policy(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeletePolicyRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_policy(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListPolicyRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListPolicyResponse>);
    fn set_policies(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::SetPoliciesRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn add_defined_set(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddDefinedSetRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_defined_set(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeleteDefinedSetRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_defined_set(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListDefinedSetRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListDefinedSetResponse>);
    fn add_statement(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddStatementRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_statement(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeleteStatementRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_statement(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListStatementRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListStatementResponse>);
    fn add_policy_assignment(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddPolicyAssignmentRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_policy_assignment(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeletePolicyAssignmentRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_policy_assignment(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListPolicyAssignmentRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListPolicyAssignmentResponse>);
    fn set_policy_assignment(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::SetPolicyAssignmentRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn add_rpki(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddRpkiRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_rpki(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeleteRpkiRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_rpki(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListRpkiRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListRpkiResponse>);
    fn enable_rpki(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::EnableRpkiRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn disable_rpki(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DisableRpkiRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn reset_rpki(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ResetRpkiRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn list_rpki_table(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::ListRpkiTableRequest, sink: ::grpcio::ServerStreamingSink<super::gobgp::ListRpkiTableResponse>);
    fn enable_zebra(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::EnableZebraRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn enable_mrt(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::EnableMrtRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn disable_mrt(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DisableMrtRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn add_bmp(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::AddBmpRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn delete_bmp(&mut self, ctx: ::grpcio::RpcContext, req: super::gobgp::DeleteBmpRequest, sink: ::grpcio::UnarySink<super::empty::Empty>);
}

pub fn create_gobgp_api<S: GobgpApi + Send + Clone + 'static>(s: S) -> ::grpcio::Service {
    let mut builder = ::grpcio::ServiceBuilder::new();
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_START_BGP, move |ctx, req, resp| {
        instance.start_bgp(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_STOP_BGP, move |ctx, req, resp| {
        instance.stop_bgp(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_GET_BGP, move |ctx, req, resp| {
        instance.get_bgp(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_PEER, move |ctx, req, resp| {
        instance.add_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_PEER, move |ctx, req, resp| {
        instance.delete_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_PEER, move |ctx, req, resp| {
        instance.list_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_UPDATE_PEER, move |ctx, req, resp| {
        instance.update_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_RESET_PEER, move |ctx, req, resp| {
        instance.reset_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_SHUTDOWN_PEER, move |ctx, req, resp| {
        instance.shutdown_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ENABLE_PEER, move |ctx, req, resp| {
        instance.enable_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DISABLE_PEER, move |ctx, req, resp| {
        instance.disable_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_MONITOR_PEER, move |ctx, req, resp| {
        instance.monitor_peer(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_PEER_GROUP, move |ctx, req, resp| {
        instance.add_peer_group(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_PEER_GROUP, move |ctx, req, resp| {
        instance.delete_peer_group(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_UPDATE_PEER_GROUP, move |ctx, req, resp| {
        instance.update_peer_group(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_DYNAMIC_NEIGHBOR, move |ctx, req, resp| {
        instance.add_dynamic_neighbor(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_PATH, move |ctx, req, resp| {
        instance.add_path(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_PATH, move |ctx, req, resp| {
        instance.delete_path(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_PATH, move |ctx, req, resp| {
        instance.list_path(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_client_streaming_handler(&METHOD_GOBGP_API_ADD_PATH_STREAM, move |ctx, req, resp| {
        instance.add_path_stream(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_GET_TABLE, move |ctx, req, resp| {
        instance.get_table(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_MONITOR_TABLE, move |ctx, req, resp| {
        instance.monitor_table(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_VRF, move |ctx, req, resp| {
        instance.add_vrf(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_VRF, move |ctx, req, resp| {
        instance.delete_vrf(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_VRF, move |ctx, req, resp| {
        instance.list_vrf(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_POLICY, move |ctx, req, resp| {
        instance.add_policy(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_POLICY, move |ctx, req, resp| {
        instance.delete_policy(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_POLICY, move |ctx, req, resp| {
        instance.list_policy(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_SET_POLICIES, move |ctx, req, resp| {
        instance.set_policies(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_DEFINED_SET, move |ctx, req, resp| {
        instance.add_defined_set(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_DEFINED_SET, move |ctx, req, resp| {
        instance.delete_defined_set(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_DEFINED_SET, move |ctx, req, resp| {
        instance.list_defined_set(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_STATEMENT, move |ctx, req, resp| {
        instance.add_statement(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_STATEMENT, move |ctx, req, resp| {
        instance.delete_statement(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_STATEMENT, move |ctx, req, resp| {
        instance.list_statement(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_POLICY_ASSIGNMENT, move |ctx, req, resp| {
        instance.add_policy_assignment(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_POLICY_ASSIGNMENT, move |ctx, req, resp| {
        instance.delete_policy_assignment(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_POLICY_ASSIGNMENT, move |ctx, req, resp| {
        instance.list_policy_assignment(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_SET_POLICY_ASSIGNMENT, move |ctx, req, resp| {
        instance.set_policy_assignment(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_RPKI, move |ctx, req, resp| {
        instance.add_rpki(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_RPKI, move |ctx, req, resp| {
        instance.delete_rpki(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_RPKI, move |ctx, req, resp| {
        instance.list_rpki(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ENABLE_RPKI, move |ctx, req, resp| {
        instance.enable_rpki(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DISABLE_RPKI, move |ctx, req, resp| {
        instance.disable_rpki(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_RESET_RPKI, move |ctx, req, resp| {
        instance.reset_rpki(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_GOBGP_API_LIST_RPKI_TABLE, move |ctx, req, resp| {
        instance.list_rpki_table(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ENABLE_ZEBRA, move |ctx, req, resp| {
        instance.enable_zebra(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ENABLE_MRT, move |ctx, req, resp| {
        instance.enable_mrt(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DISABLE_MRT, move |ctx, req, resp| {
        instance.disable_mrt(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_ADD_BMP, move |ctx, req, resp| {
        instance.add_bmp(ctx, req, resp)
    });
    let mut instance = s;
    builder = builder.add_unary_handler(&METHOD_GOBGP_API_DELETE_BMP, move |ctx, req, resp| {
        instance.delete_bmp(ctx, req, resp)
    });
    builder.build()
}
