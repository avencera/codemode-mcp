import CompanionCore
import SwiftUI

/// Pairing until a gateway is paired; then the read waiting on the owner if
/// there is one, else the gateway
struct ContentView: View {
    @Environment(AppManager.self) private var manager

    var body: some View {
        NavigationStack {
            if manager.state.gateway == nil {
                PairView()
            } else if let read = manager.shownRead {
                // a view of its own per read, so nothing entered or attached
                // for one is ever sent for the next
                RequestView(read: read)
                    .id(read.id)
            } else {
                GatewayView()
            }
        }
    }
}
