import SwiftUI
import UmbrellaFFI

/// Smoke-test UI: 6 кнопок — по одной на scenario. Тап запускает
/// `TestScenariosViewModel.run(kind)` и показывает статус (idle / running /
/// success / failure + message).
///
/// Secrets never cross this boundary — `KeyStoreBridge` хранит seed в
/// Keychain locally, FFI получает только mnemonic phrase string.
///
/// Smoke-test UI: 6 buttons — one per scenario. A tap invokes
/// `TestScenariosViewModel.run(kind)` and renders the status.
///
/// Secrets never cross this boundary — `KeyStoreBridge` keeps the seed in
/// Keychain locally, FFI only receives the mnemonic phrase string.
struct ContentView: View {
    @StateObject private var vm = TestScenariosViewModel()

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Ручной чек-лист (реальное устройство)")) {
                    ForEach(ScenarioKind.allCases, id: \.self) { kind in
                        ScenarioRow(kind: kind, vm: vm)
                    }
                }
                Section(header: Text("Логи")) {
                    ForEach(vm.logs, id: \.self) { log in
                        Text(log).font(.system(.caption, design: .monospaced))
                    }
                }
            }
            .navigationTitle("Umbrella Test Harness")
        }
    }
}

/// Одна строка списка сценариев.
///
/// A single scenario list row.
struct ScenarioRow: View {
    let kind: ScenarioKind
    @ObservedObject var vm: TestScenariosViewModel

    var body: some View {
        HStack {
            Text(kind.title)
            Spacer()
            switch vm.state(for: kind) {
            case .idle:
                Button("Run") { vm.run(kind) }
            case .running:
                ProgressView()
            case .success:
                Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
            case .failure(let msg):
                VStack(alignment: .trailing) {
                    Image(systemName: "xmark.circle.fill").foregroundColor(.red)
                    Text(msg).font(.caption).foregroundColor(.red)
                }
            }
        }
    }
}
