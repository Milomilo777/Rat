use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, ERROR_SUCCESS};
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmProviderAdd0, FwpmSubLayerAdd0,
    FwpmGetAppIdFromFileName0, FwpmFreeMemory0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
    FWPM_ACTION0, FWP_ACTION_BLOCK, FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_EMPTY,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWPM_DISPLAY_DATA0,
    FWP_VALUE0
};

const PROVIDER_KEY: GUID = GUID::from_values(0x12345678, 0x1234, 0x1234, [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
const SUBLAYER_KEY: GUID = GUID::from_values(0x87654321, 0x4321, 0x4321, [0x87, 0x65, 0x43, 0x21, 0xfe, 0xdc, 0xba, 0x09]);
const FWPM_SUBLAYER_WEIGHT_MAX: u16 = 65535;

fn main() {
    println!("Starting Windows WFP Spike...");

    unsafe {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };

        let mut engine_handle = HANDLE::default();
        let status = FwpmEngineOpen0(
            None,
            RPC_C_AUTHN_DEFAULT as u32,
            None,
            Some(&session),
            &mut engine_handle,
        );

        if status != ERROR_SUCCESS.0 {
            eprintln!("Failed to open WFP engine. Are you running as Admin? Error: {}", status);
            return;
        }

        println!("WFP Engine opened successfully.");

        // Add Provider
        let mut provider_name: Vec<u16> = "Rat Spike Provider\0".encode_utf16().collect();
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR::from_raw(provider_name.as_mut_ptr()),
                ..Default::default()
            },
            ..Default::default()
        };

        let status = FwpmProviderAdd0(engine_handle, &provider, None);
        if status != ERROR_SUCCESS.0 {
            eprintln!("Failed to add provider: {}", status);
            let _ = FwpmEngineClose0(engine_handle);
            return;
        }
        println!("Provider added.");

        // Add Sublayer
        let mut sublayer_name: Vec<u16> = "Rat Spike Sublayer\0".encode_utf16().collect();
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR::from_raw(sublayer_name.as_mut_ptr()),
                ..Default::default()
            },
            providerKey: &PROVIDER_KEY as *const _ as *mut _,
            weight: FWPM_SUBLAYER_WEIGHT_MAX,
            ..Default::default()
        };

        let status = FwpmSubLayerAdd0(engine_handle, &sublayer, None);
        if status != ERROR_SUCCESS.0 {
            eprintln!("Failed to add sublayer: {}", status);
            let _ = FwpmEngineClose0(engine_handle);
            return;
        }
        println!("Sublayer added.");

        // Get App ID (example path)
        let app_path: Vec<u16> = "C:\\Windows\\System32\\curl.exe\0".encode_utf16().collect();
        let mut app_blob = std::ptr::null_mut();

        let status = FwpmGetAppIdFromFileName0(PCWSTR::from_raw(app_path.as_ptr()), &mut app_blob);
        if status != ERROR_SUCCESS.0 {
            eprintln!("Failed to get App ID: {}", status);
            let _ = FwpmEngineClose0(engine_handle);
            return;
        }
        println!("App ID obtained for curl.exe.");

        // Add Filter V4
        let condition_value_anon = if !app_blob.is_null() {
            FWP_CONDITION_VALUE0_0 { byteBlob: &mut *app_blob }
        } else {
            FWP_CONDITION_VALUE0_0 { byteBlob: std::ptr::null_mut() }
        };

        let mut condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: condition_value_anon,
            },
        };

        let action = FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            ..Default::default()
        };

        let filter_v4 = FWPM_FILTER0 {
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            action,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_EMPTY,
                ..Default::default()
            },
            numFilterConditions: 1,
            filterCondition: &mut condition,
            ..Default::default()
        };

        let mut filter_id_v4 = 0;
        let status = FwpmFilterAdd0(engine_handle, &filter_v4, None, Some(&mut filter_id_v4));
        if status != ERROR_SUCCESS.0 {
            eprintln!("Failed to add V4 filter: {}", status);
        } else {
            println!("V4 Filter added successfully (ID {}).", filter_id_v4);
        }

        // Add Filter V6
        let mut filter_v6 = filter_v4; // Copy configuration
        filter_v6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

        let mut filter_id_v6 = 0;
        let status = FwpmFilterAdd0(engine_handle, &filter_v6, None, Some(&mut filter_id_v6));
        if status != ERROR_SUCCESS.0 {
            eprintln!("Failed to add V6 filter: {}", status);
        } else {
            println!("V6 Filter added successfully (ID {}).", filter_id_v6);
        }

        if !app_blob.is_null() {
            FwpmFreeMemory0(&mut app_blob as *mut _ as *mut *mut _);
        }

        println!("Spike active. Press Enter to clean up and exit...");
        let _ = std::io::stdin().read_line(&mut String::new());

        // Because we used FWPM_SESSION_FLAG_DYNAMIC, FwpmEngineClose0 will automatically
        // remove the filters, sublayer, and provider upon closing.
        let _ = FwpmEngineClose0(engine_handle);
        println!("Cleaned up. Exiting.");
    }
}
