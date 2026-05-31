import '@servicenow/sdk/global'

declare global {
    namespace Now {
        namespace Internal {
            interface Keys extends KeysRegistry {
                explicit: {
                    acl_audit_read: {
                        table: 'sys_security_acl'
                        id: '7f3d6f66f3b14376b166cfbdd7883d13'
                    }
                    acl_audit_write: {
                        table: 'sys_security_acl'
                        id: '1d5af512b8ff40d298db336ef79c60f0'
                    }
                    acl_executor: {
                        table: 'sys_security_acl'
                        id: '638c1394dc714abdbb97f8f7b23d57ba'
                    }
                    api_x_mcp: {
                        table: 'sys_ws_definition'
                        id: 'cebf7ae8cc30422cb7b7dc8d39eef9b8'
                    }
                    bom_json: {
                        table: 'sys_module'
                        id: '2602f92483974a63a4189909a96e8c0d'
                    }
                    job_nonce_purge: {
                        table: 'sysauto_script'
                        id: '3a287b0551cd43c9923117dfbfb13db9'
                    }
                    p_egress: {
                        table: 'sys_properties'
                        id: '1dcf5154374b48a9bee4ee304c5040f5'
                    }
                    p_enabled: {
                        table: 'sys_properties'
                        id: 'b39be9c926f149cca8b01403ac479b59'
                    }
                    p_hmac: {
                        table: 'sys_properties'
                        id: '39c44f1928324c2ea0e058b024966061'
                    }
                    p_hmac_prev: {
                        table: 'sys_properties'
                        id: '632b71c0cb2844a6b8ea6b3d9794a383'
                    }
                    p_maxb: {
                        table: 'sys_properties'
                        id: '73668da71cf947fbb0aade30892fc668'
                    }
                    p_maxout: {
                        table: 'sys_properties'
                        id: 'f738cea9874b479b88760614aaa0cc72'
                    }
                    p_timeout: {
                        table: 'sys_properties'
                        id: 'd548c7b87a914b5692126ab04cf5b325'
                    }
                    package_json: {
                        table: 'sys_module'
                        id: 'dfb5de966d0c44279da72668b6dcbc2f'
                    }
                    route_run: {
                        table: 'sys_ws_operation'
                        id: '9fbdbaef367446c4b028acbeb573ca45'
                    }
                    si_verify: {
                        table: 'sys_script_include'
                        id: '972e97b7959e4692951be09086c4eb0c'
                        deleted: true
                    }
                    src_server_x_mcp_executor_js: {
                        table: 'sys_module'
                        id: 'f6d6544c00944689883e86edd016fab4'
                    }
                    src_server_x_mcp_verify_js: {
                        table: 'sys_module'
                        id: '4cba8aca48134fe282247c21bff7c6b2'
                    }
                }
                composite: [
                    {
                        table: 'sys_dictionary'
                        id: '0382d78411a942f6992a914e7386df3c'
                        key: {
                            name: 'x_1793136_mcp_nonce'
                            element: 'NULL'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '05bc7d48a1244791aa23c5cd61696ccf'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'status'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '13d128f0ae30406f8a1fd706123627d3'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'output_size'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '1e9aad18129a485fbfc11e065cda049b'
                        key: {
                            name: 'x_1793136_mcp_nonce'
                            element: 'value'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '253a1d8e79e44c9eafe3ba13cea816d0'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'actor_verified'
                        }
                    },
                    {
                        table: 'sys_index'
                        id: '27cbefcc28fe4822ae25b9fe5fb8adae'
                        key: {
                            logical_table_name: 'x_1793136_mcp_nonce'
                            col_name_string: 'value'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '2a35b1fb0e78451b8a45fbb4dd97c530'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'request_id'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_user_role'
                        id: '2cd1043150cc40da97b3dd4dae45f3ae'
                        key: {
                            name: 'x_1793136_mcp.admin'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '32ccf67752494b148099a69e3df3d55f'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'duration'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '398ff8ec2cc54170814960ed8f6ee8ae'
                        key: {
                            name: 'x_1793136_mcp_nonce'
                            element: 'created'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '4cedf6f0dcce411a811a69f97fb51453'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'code_size'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '505a20f0fc104ed29db31017e2fd7a63'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'code_size'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '511a96f8163b4a6e881e841efbe9b798'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'mcp_actor_user_id'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '54f10613d13d47ddb2ecb644f921465e'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'code_hash'
                            language: 'en'
                        }
                    },
                    {
                        table: 'ua_table_licensing_config'
                        id: '57191403f2bc4447beb23e52deb5c49d'
                        key: {
                            name: 'x_1793136_mcp_nonce'
                        }
                    },
                    {
                        table: 'sys_db_object'
                        id: '59cce9304daa45d8bf4e72e8ecf6fcfa'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '5fe3a74f3921488ba396a9f0b4e156f1'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'request_id'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '66fa92e58b844606a07f6df6e2910814'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'NULL'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '6f5c9b8dd300466aaaf3e0eddf0ebda2'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'NULL'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '7810820fb08c4333ac17a135c4bfa44f'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'code_hash'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '7cef3f85a95a473a8459c0299eace32b'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'status'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '8b1e0497d60a44ff906b5931474fff40'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'mcp_actor_email'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '93a0be6cb94b4e7ea6d885f23d073ef7'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'snow_user_name'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '951f2b782ced4afbb4c51278de5ca66c'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'started_at'
                            language: 'en'
                        }
                    },
                    {
                        table: 'ua_table_licensing_config'
                        id: '9558ded7674140ffb9badf619aeacb79'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: '9d2d294fedef4ea9a1d805e62f6c0c8a'
                        key: {
                            name: 'x_1793136_mcp_nonce'
                            element: 'NULL'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: '9eb1ae1699cf48afbb0352dfa40996e6'
                        key: {
                            name: 'x_1793136_mcp_nonce'
                            element: 'created'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: 'a414f3de68064d4198700ac15cb42cc9'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'error_class'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_security_acl_role'
                        id: 'a6e0167eec5041528416f38de658ab0a'
                        key: {
                            sys_security_acl: '1d5af512b8ff40d298db336ef79c60f0'
                            sys_user_role: {
                                id: '2cd1043150cc40da97b3dd4dae45f3ae'
                                key: {
                                    name: 'x_1793136_mcp.admin'
                                }
                            }
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: 'ae38cb433f524fb2b5d725310705a4c5'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'mcp_actor_email'
                        }
                    },
                    {
                        table: 'sys_security_acl_role'
                        id: 'ae6d0503965e493eb264b63d464e47e0'
                        key: {
                            sys_security_acl: '7f3d6f66f3b14376b166cfbdd7883d13'
                            sys_user_role: {
                                id: '2cd1043150cc40da97b3dd4dae45f3ae'
                                key: {
                                    name: 'x_1793136_mcp.admin'
                                }
                            }
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: 'aff60999b1444a028df7940cece3526a'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'snow_user'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: 'b3e6661bab6d4610ab447ddf2d001776'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'error_class'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: 'bb9dfe244bcd417980fd02a638f155d9'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'output_size'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: 'bf0bff4cf08049ef8604734495b52765'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'snow_user_name'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: 'd2b7d12a7a4c4df3b1b53d6efd6e4bf0'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'actor_verified'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_user_role'
                        id: 'd9ba53ae75ff4a78b9178cd7f528ca90'
                        key: {
                            name: 'x_1793136_mcp.executor'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: 'dab8f45772fc4d7cbad9b05555380c8c'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'snow_user'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: 'dd079d9a5b4c425c8ff6f50f9730060c'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'mcp_actor_user_id'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: 'dde62391dcfb4f9da9a2598bf75677db'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'reason'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: 'e2a40b16b169497aba1e267782af0fb9'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'started_at'
                        }
                    },
                    {
                        table: 'sys_db_object'
                        id: 'e422231ff93d442a93273c0c10747541'
                        key: {
                            name: 'x_1793136_mcp_nonce'
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: 'e47068c725a149e2a8be145bc29f3966'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'reason'
                            language: 'en'
                        }
                    },
                    {
                        table: 'sys_dictionary'
                        id: 'e70de3609fc14aa496f5fb920557c0e8'
                        key: {
                            name: 'x_1793136_mcp_audit_log'
                            element: 'duration'
                        }
                    },
                    {
                        table: 'sys_security_acl_role'
                        id: 'fb824384a82a42188e49f7610de8ad16'
                        key: {
                            sys_security_acl: '638c1394dc714abdbb97f8f7b23d57ba'
                            sys_user_role: {
                                id: 'd9ba53ae75ff4a78b9178cd7f528ca90'
                                key: {
                                    name: 'x_1793136_mcp.executor'
                                }
                            }
                        }
                    },
                    {
                        table: 'sys_documentation'
                        id: 'fc8aed5580ef4e45bc4954ba26e321c1'
                        key: {
                            name: 'x_1793136_mcp_nonce'
                            element: 'value'
                            language: 'en'
                        }
                    },
                ]
            }
        }
    }
}
