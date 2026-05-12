import SwiftUI
import UmbrellaFFI

/// SwiftUI `@main` entry — минимальное iOS приложение для запуска 6
/// смоук-сценариев на реальном iPhone.
///
/// SwiftUI `@main` entry — minimal iOS app running the six smoke scenarios
/// on a real iPhone.
@main
struct UmbrellaTestHarnessApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
