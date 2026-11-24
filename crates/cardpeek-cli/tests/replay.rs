//! CLI replay integration tests.

use assert_cmd::Command;
use predicates::str::contains;

const EXPECTED: &str = include_str!("../../../tests/fixtures/documents/atr-synthetic-001.json");
const GSM_USIM_EXPECTED: &str =
    include_str!("../../../tests/fixtures/documents/gsm-usim-synthetic-001.json");

const PORTED_FIXTURES: &[(&str, &str, &str)] = &[
    ("openpgp", "openpgp-synthetic-001", "Exported 41 nodes"),
    (
        "finnish-etravel",
        "finnish-etravel-synthetic-001",
        "Exported 43 nodes",
    ),
    ("emv", "emv-synthetic-001", "Exported 20 nodes"),
    ("thai-eid", "thai-eid-synthetic-001", "Exported 28 nodes"),
    ("fineid", "fineid-synthetic-001", "Exported 53 nodes"),
    ("moneo", "moneo-synthetic-001", "Exported 42 nodes"),
    ("mifare", "mifare-synthetic-001", "Exported 91 nodes"),
    (
        "belgian-eid",
        "belgian-eid-synthetic-001",
        "Exported 26 nodes",
    ),
    ("vitale-2", "vitale-2-synthetic-001", "Exported 18 nodes"),
    ("calypso", "calypso-synthetic-001", "Exported 239 nodes"),
    (
        "tachograph",
        "tachograph-synthetic-001",
        "Exported 40 nodes",
    ),
    (
        "gsm-legacy",
        "gsm-legacy-synthetic-001",
        "Exported 66 nodes",
    ),
    (
        "e-passport",
        "e-passport-synthetic-001",
        "Exported 58 nodes",
    ),
];

fn fixture(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn analysers() -> String {
    format!("{}/../../analysers", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn replay_waits_for_operations_with_more_than_128_events() {
    let directory = tempfile::tempdir().unwrap();
    let analysers = directory.path().join("analysers");
    std::fs::create_dir_all(analysers.join("cards")).unwrap();
    std::fs::write(
        analysers.join("cards/many.lua"),
        r"-- @id many
-- @title Many exchanges
-- @description Exercise long replay operations
-- @version 1.0.0
-- @capabilities live, replay
local cardpeek = require('cardpeek')
local command = cardpeek.bytes.from_hex('00B0000000')
for _ = 1, 65 do
  local response, failure = cardpeek.card.transmit(command)
  assert(failure == nil, failure and failure.message or 'APDU failed')
  assert(response.status == 0x9000)
end
local root = cardpeek.nodes.root()
root:append('card', 'Long replay')
cardpeek.log.info('Completed 65 exchanges')
",
    )
    .unwrap();
    let mut records = vec![serde_json::json!({
        "kind": "reset",
        "mode": "cold",
        "atr": { "width": 8, "elements": [59, 143, 128] },
        "id": "long-reset"
    })];
    for index in 0..65 {
        records.push(serde_json::json!({
            "id": format!("long-command-{index}"),
            "kind": "command",
            "command": [0, 176, 0, 0, 0],
            "response": { "data": [], "status": 36864 }
        }));
    }
    let trace = directory.path().join("long.json");
    std::fs::write(
        &trace,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "records": records
        }))
        .unwrap(),
    )
    .unwrap();
    let output = directory.path().join("long-result.json");
    Command::cargo_bin("cardpeek")
        .unwrap()
        .arg("replay")
        .arg(trace)
        .arg("--analysers")
        .arg(analysers)
        .arg("many")
        .arg("--output")
        .arg(&output)
        .assert()
        .success()
        .stdout(contains("Exported 1 nodes in revision 1"))
        .stderr(contains("Info: Completed 65 exchanges"));
    assert!(output.is_file());
}

#[test]
fn discovers_analysers_without_executing_them() {
    Command::cargo_bin("cardpeek")
        .unwrap()
        .arg("discover")
        .arg(analysers())
        .assert()
        .success()
        .stdout(contains("atr"))
        .stdout(contains("belgian-eid"))
        .stdout(contains("calypso"))
        .stdout(contains("e-passport"))
        .stdout(contains("finnish-etravel"))
        .stdout(contains("emv"))
        .stdout(contains("fineid"))
        .stdout(contains("gsm-legacy"))
        .stdout(contains("gsm-usim"))
        .stdout(contains("mifare"))
        .stdout(contains("moneo"))
        .stdout(contains("openpgp"))
        .stdout(contains("tachograph"))
        .stdout(contains("thai-eid"))
        .stdout(contains("vitale-2"));
}

fn copy_analyser_resources(destination: &std::path::Path) {
    fn copy(source: &std::path::Path, destination: &std::path::Path) {
        for entry in std::fs::read_dir(source).unwrap() {
            let source_path = entry.unwrap().path();
            let destination_path = destination.join(source_path.strip_prefix(source).unwrap());
            if source_path.is_dir() {
                std::fs::create_dir(&destination_path).unwrap();
                copy(&source_path, &destination_path);
            } else {
                std::fs::copy(source_path, destination_path).unwrap();
            }
        }
    }
    std::fs::create_dir(destination).unwrap();
    copy(std::path::Path::new(&analysers()), destination);
}

#[test]
fn replay_exports_the_expected_native_document() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("atr-result.json");
    Command::cargo_bin("cardpeek")
        .unwrap()
        .arg("replay")
        .arg(fixture("traces/atr-synthetic-001.json"))
        .arg("--analysers")
        .arg(analysers())
        .arg("atr")
        .arg("--output")
        .arg(&output)
        .assert()
        .success()
        .stdout(contains("Exported 2 nodes in revision 1"))
        .stderr(contains("Info: Read 2 ATR bytes"));
    assert_eq!(std::fs::read_to_string(output).unwrap(), EXPECTED);
}

#[test]
fn replays_gsm_usim_files_and_preserves_read_only_behaviour() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("gsm-usim-result.json");
    Command::cargo_bin("cardpeek")
        .unwrap()
        .arg("replay")
        .arg(fixture("traces/gsm-usim-synthetic-001.json"))
        .arg("--analysers")
        .arg(analysers())
        .arg("gsm-usim")
        .arg("--output")
        .arg(&output)
        .assert()
        .success()
        .stdout(contains("Exported 69 nodes in revision 1"))
        .stderr(contains("Info: Selected 10 files and read 1 records"));
    let actual = std::fs::read_to_string(output).unwrap();
    assert_eq!(actual, GSM_USIM_EXPECTED);
    assert!(actual.contains("Text:\\nHello"));
    assert!(actual.contains("Sensitive content not read"));
    assert!(!actual.contains("VERIFY"));
}

#[test]
fn usim_selection_retries_legacy_variants_after_6b00() {
    for without_le in [false, true] {
        let mut trace: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/traces/gsm-usim-synthetic-001.json"
        ))
        .unwrap();
        let records = trace["records"].as_array_mut().unwrap();
        let application_index = records
            .iter()
            .position(|record| {
                record["kind"] == "command"
                    && record["command"][0] == 0
                    && record["command"][1] == 164
                    && record["command"][2] == 4
            })
            .unwrap();
        let mut legacy_records = records[application_index + 1..].to_vec();
        for record in &mut legacy_records {
            record["command"][0] = serde_json::json!(0xa0);
            if record["command"][1] == 164 && record["command"][2] == 2 {
                record["command"][2] = serde_json::json!(0);
            }
            record["id"] = serde_json::json!(format!("legacy-{}", record["id"].as_str().unwrap()));
        }
        let application = &mut records[application_index];
        let command = application["command"].as_array().unwrap().clone();
        let data = application["response"]["data"].clone();
        application["response"]["data"] = serde_json::json!([]);
        application["response"]["status"] = serde_json::json!(0x6b00);
        let mut legacy = command.clone();
        legacy[0] = serde_json::json!(0xa0);
        let status = if without_le { 0x6b00 } else { 0x9000 };
        records.push(serde_json::json!({
            "id": "legacy-usim-select",
            "kind": "command",
            "command": legacy,
            "response": { "data": data, "status": status }
        }));
        if without_le {
            let mut without_le_command = command;
            without_le_command[0] = serde_json::json!(0xa0);
            without_le_command.pop();
            records.push(serde_json::json!({
                "id": "legacy-usim-select-without-le",
                "kind": "command",
                "command": without_le_command,
                "response": { "data": data, "status": 0x9000 }
            }));
        }
        records.extend(legacy_records);
        let directory = tempfile::tempdir().unwrap();
        let trace_path = directory.path().join("legacy.json");
        std::fs::write(&trace_path, serde_json::to_vec(&trace).unwrap()).unwrap();
        let output = directory.path().join("legacy-result.json");
        Command::cargo_bin("cardpeek")
            .unwrap()
            .arg("replay")
            .arg(trace_path)
            .arg("--analysers")
            .arg(analysers())
            .arg("gsm-usim")
            .arg("--output")
            .arg(&output)
            .assert()
            .success();
        let result = std::fs::read_to_string(output).unwrap();
        assert!(result.contains("ADF.USIM"));
        assert!(result.contains("class A0"));
        assert_eq!(result.contains("without an Le byte"), without_le);
        assert!(!result.contains("USIM selection failed"));
    }
}

#[test]
fn rejects_an_analyser_that_was_not_discovered() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("unused.json");
    Command::cargo_bin("cardpeek")
        .unwrap()
        .arg("replay")
        .arg(fixture("traces/atr-synthetic-001.json"))
        .arg("--analysers")
        .arg(analysers())
        .arg("missing")
        .arg("--output")
        .arg(&output)
        .assert()
        .failure()
        .stderr(contains("analyser missing was not discovered"));
    assert!(!output.exists());
}

#[test]
fn manages_and_uses_the_platform_analyser_library() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config");
    let library = config.join("cardpeek-ng/analysers");
    let mut command = Command::cargo_bin("cardpeek").unwrap();
    command
        .env("XDG_CONFIG_HOME", &config)
        .arg("analysers")
        .arg("list")
        .assert()
        .success()
        .stdout(contains("atr"))
        .stdout(contains("gsm-usim"));
    let mut bundled = 0;
    for source in std::fs::read_dir(format!("{}/cards", analysers())).unwrap() {
        let source = source.unwrap().path();
        if source
            .extension()
            .is_some_and(|extension| extension == "lua")
        {
            let destination = library.join("cards").join(source.file_name().unwrap());
            assert_eq!(
                std::fs::read(destination).unwrap(),
                std::fs::read(source).unwrap()
            );
            bundled += 1;
        }
    }
    assert!(bundled > 0);
    for resource in [
        "shared/lib/util.lua",
        "shared/data/country-codes.lua",
        "shared/calypso/france/intercode.lua",
        "shared/data/smartcard_list.txt",
    ] {
        assert_eq!(
            std::fs::read(library.join(resource)).unwrap(),
            std::fs::read(std::path::Path::new(&analysers()).join(resource)).unwrap()
        );
    }
    let custom = directory.path().join("cards/custom.lua");
    std::fs::create_dir_all(custom.parent().unwrap()).unwrap();
    std::fs::write(
        &custom,
        "-- @id custom\n-- @title Custom\n-- @description Test import\n-- @version 1.0.0\n",
    )
    .unwrap();
    let mut command = Command::cargo_bin("cardpeek").unwrap();
    command
        .env("XDG_CONFIG_HOME", &config)
        .arg("analysers")
        .arg("import")
        .arg(directory.path())
        .assert()
        .success()
        .stdout(contains("Imported custom"));
    assert!(library.join("cards/custom.lua").is_file());

    let mut command = Command::cargo_bin("cardpeek").unwrap();
    command
        .env("XDG_CONFIG_HOME", &config)
        .arg("analysers")
        .arg("list")
        .assert()
        .success()
        .stdout(contains("atr"))
        .stdout(contains("gsm-usim"));

    let output = directory.path().join("library-result.json");
    let mut command = Command::cargo_bin("cardpeek").unwrap();
    command
        .env("XDG_CONFIG_HOME", &config)
        .arg("replay")
        .arg(fixture("traces/atr-synthetic-001.json"))
        .arg("atr")
        .arg("--output")
        .arg(&output)
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(output).unwrap(), EXPECTED);

    let mut command = Command::cargo_bin("cardpeek").unwrap();
    command
        .env("XDG_CONFIG_HOME", &config)
        .arg("analysers")
        .arg("remove")
        .arg("atr")
        .assert()
        .success()
        .stdout(contains("Removed atr"));
    assert!(!library.join("cards/atr.lua").exists());
    assert!(library.join("cards/gsm-usim.lua").is_file());

    let mut command = Command::cargo_bin("cardpeek").unwrap();
    command
        .env("XDG_CONFIG_HOME", &config)
        .arg("analysers")
        .arg("list")
        .assert()
        .success();
    assert!(!library.join("cards/atr.lua").exists());
}

#[test]
fn replays_every_ported_analyser_against_synthetic_fixtures() {
    fn fixture_path(name: &str) -> String {
        fixture(name)
    }
    for (analyser, fixture, expected_nodes) in PORTED_FIXTURES {
        let directory = tempfile::tempdir().unwrap();
        let resources = directory.path().join("analysers");
        copy_analyser_resources(&resources);
        if *analyser == "e-passport" {
            let path = resources.join("cards/e-passport.lua");
            let source = std::fs::read_to_string(&path).unwrap();
            let old = "local function prompt(prompt)\n  local ok, value = pcall(cp.ui.text, prompt, '')\n  return ok and value or ''\nend";
            let new = "local answers = { '123456789', '010101', '010101' }\nlocal function prompt(_) return table.remove(answers, 1) end";
            std::fs::write(&path, source.replace(old, new)).unwrap();
        }
        if *analyser == "finnish-etravel" {
            let path = resources.join("cards/finnish-etravel.lua");
            let source = std::fs::read_to_string(&path).unwrap();
            let old = "local function secret(prompt)\n  return cp.ui.secret(prompt) or ''\nend";
            let new = "local function secret(_) return '123456' end\nlocal function scalar(value)\n  return cp.bytes.pack(8, string.rep('00', 47), string.format('%02X', value))\nend";
            let source = source.replace(old, new);
            let old = "local session = cp.crypto.pace_new(credential, cp.bytes.from_string(value))";
            let new = "local session = cp.crypto.pace_new(credential, cp.bytes.from_string(value), scalar(3), scalar(4))";
            let source = source.replace(old, new);
            let old = "local method = cp.ui.question('Use CAN for PACE? Cancel to use the machine-readable zone.')";
            let new = "local method = true";
            std::fs::write(&path, source.replace(old, new)).unwrap();
        }

        let output = directory.path().join("result.json");
        Command::cargo_bin("cardpeek")
            .unwrap()
            .arg("replay")
            .arg(fixture_path(&format!("traces/{fixture}.json")))
            .arg("--analysers")
            .arg(&resources)
            .arg(analyser)
            .arg("--output")
            .arg(&output)
            .assert()
            .success()
            .stdout(contains(*expected_nodes));
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            std::fs::read_to_string(fixture_path(&format!("documents/{fixture}.json"))).unwrap(),
            "unexpected document for {analyser}"
        );
    }
}

#[test]
fn fineid_retries_length_and_get_response_statuses() {
    fn replay_variant(
        records: &mut Vec<serde_json::Value>,
        target: &str,
        inserted: serde_json::Value,
    ) {
        let index = records
            .iter()
            .position(|record| record["id"] == target)
            .unwrap();
        let data = records[index]["response"]["data"].clone();
        records[index]["response"]["status"] = inserted["status"].clone();
        if inserted["command"][1] == 192 {
            records[index]["response"]["data"] = serde_json::json!(data.as_array().unwrap()[..8]);
        } else {
            records[index]["response"]["data"] = serde_json::json!([]);
        }
        let mut response = inserted;
        response.as_object_mut().unwrap().remove("status");
        let response_data = if response["command"][1] == 192 {
            serde_json::json!(data.as_array().unwrap()[8..])
        } else {
            data
        };
        response["response"] = serde_json::json!({ "data": response_data, "status": 0x9000 });
        records.insert(index + 1, response);
    }

    let directory = tempfile::tempdir().unwrap();
    for (name, target, inserted) in [
        (
            "length",
            "record-0007",
            serde_json::json!({
                "id": "retry-length",
                "kind": "command",
                "command": [0, 176, 0, 0, 80],
                "status": 0x6c50
            }),
        ),
        (
            "response",
            "record-0011",
            serde_json::json!({
                "id": "get-response",
                "kind": "command",
                "command": [0, 192, 0, 0, 0],
                "status": 0x6100
            }),
        ),
    ] {
        let mut trace: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/traces/fineid-synthetic-001.json"
        ))
        .unwrap();
        replay_variant(trace["records"].as_array_mut().unwrap(), target, inserted);
        let trace_path = directory.path().join(format!("{name}.json"));
        std::fs::write(&trace_path, serde_json::to_vec(&trace).unwrap()).unwrap();
        let output = directory.path().join(format!("{name}-result.json"));
        Command::cargo_bin("cardpeek")
            .unwrap()
            .arg("replay")
            .arg(trace_path)
            .arg("--analysers")
            .arg(analysers())
            .arg("fineid")
            .arg("--output")
            .arg(&output)
            .assert()
            .success();
        let actual = std::fs::read_to_string(output).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&actual).unwrap();
        let baseline: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(fixture("documents/fineid-synthetic-001.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(actual["id"], format!("doc-{name}"));
        assert_eq!(actual["run_id"], format!("run-{name}"));
        assert_eq!(actual["roots"], baseline["roots"]);
    }
}

#[test]
fn calypso_family_modules_load_with_native_api() {
    let directory = tempfile::tempdir().unwrap();
    let resources = directory.path().join("analysers");
    copy_analyser_resources(&resources);
    let source = r"-- @id module-check
    -- @title Calypso module check
    -- @description Load all Calypso family modules
    -- @version 1.0.0
            local cp = require('cardpeek')
            local modules = {
              'shared.calypso.belgium.mobib',
              'shared.calypso.portugal.viva',
              'shared.calypso.france.intercode',
              'shared.calypso.france.grenoble-tag',
              'shared.calypso.france.montpellier-tam',
              'shared.calypso.france.paris-navigo',
              'shared.calypso.france.bordeaux-tbc',
              'shared.calypso.israel.ravkav',
              'shared.calypso.israel.ravkav-dan'
            }
            for _, name in ipairs(modules) do
              local ok, result = pcall(require, name)
              assert(ok, name .. ': ' .. tostring(result))
              assert(type(result) == 'function', name .. ' did not return a decoder')
            end
        ";
    let path = resources.join("cards/module-check.lua");
    std::fs::write(&path, source).unwrap();
    let trace = directory.path().join("trace.json");
    std::fs::write(
            &trace,
            r#"{"schema_version":1,"records":[{"kind":"reset","mode":"cold","atr":{"width":8,"elements":[59,0]},"id":"reset-1"}]}"#,
        )
        .unwrap();
    Command::cargo_bin("cardpeek")
        .unwrap()
        .arg("replay")
        .arg(trace)
        .arg("--analysers")
        .arg(&resources)
        .arg("module-check")
        .arg("--output")
        .arg(directory.path().join("result.json"))
        .assert()
        .success();
}

#[test]
fn ported_analysers_do_not_publish_authentication_secrets() {
    let mifare = std::fs::read_to_string(fixture("documents/mifare-synthetic-001.json")).unwrap();
    assert!(mifare.contains("KeyA:(redacted)"));
    assert!(mifare.contains("keyB:(redacted)"));
    assert!(!mifare.contains("FFFFFFFFFFFF"));
    let passport =
        std::fs::read_to_string(fixture("documents/e-passport-synthetic-001.json")).unwrap();
    assert!(!passport.contains("123456789"));
    assert!(!passport.contains("010101"));
    let passport_source = std::fs::read_to_string(format!(
        "{}/../../analysers/cards/e-passport.lua",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(!passport_source.contains("MRZ data:"));
    assert!(!passport_source.contains("CARDPEEK_TEST_MRZ"));
}
