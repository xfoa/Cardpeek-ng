//! CLI replay integration tests.

use assert_cmd::Command;
use predicates::str::contains;

const EXPECTED: &str = include_str!("../../../tests/fixtures/documents/atr-synthetic-001.json");
const GSM_USIM_EXPECTED: &str =
    include_str!("../../../tests/fixtures/documents/gsm-usim-synthetic-001.json");

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
    std::fs::create_dir(&analysers).unwrap();
    std::fs::write(
        analysers.join("many.lua"),
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
        .stdout("ID        VERSION  TITLE             DESCRIPTION\natr       1.0.0    Card read         Read the current Answer to Reset\ngsm-usim  1.0.0    GSM SIM and USIM  Inspect GSM SIM and USIM files with optional PIN1 verification\n");
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
    for source in std::fs::read_dir(analysers()).unwrap() {
        let source = source.unwrap().path();
        if source
            .extension()
            .is_some_and(|extension| extension == "lua")
        {
            let destination = library.join(source.file_name().unwrap());
            assert_eq!(
                std::fs::read(destination).unwrap(),
                std::fs::read(source).unwrap()
            );
            bundled += 1;
        }
    }
    assert!(bundled > 0);
    let custom = directory.path().join("custom.lua");
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
    assert!(library.join("custom.lua").is_file());

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
    assert!(!library.join("atr.lua").exists());
    assert!(library.join("gsm_usim.lua").is_file());

    let mut command = Command::cargo_bin("cardpeek").unwrap();
    command
        .env("XDG_CONFIG_HOME", &config)
        .arg("analysers")
        .arg("list")
        .assert()
        .success();
    assert!(!library.join("atr.lua").exists());
}
