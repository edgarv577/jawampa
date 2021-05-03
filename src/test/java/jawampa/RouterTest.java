package jawampa;

import jawampa.transport.netty.SimpleWampWebsocketListener;
import java.net.URI;

public class RouterTest {

   public static void main(String[] args) {
      new RouterTest().start();
   }

   public void start() {

      WampRouterBuilder routerBuilder = new WampRouterBuilder();
      WampRouter router;
      try {
         routerBuilder.addRealm("com.magenta.test");
         router = routerBuilder.build();
      } catch (ApplicationError e1) {
         e1.printStackTrace();
         return;
      }

      URI serverUri = URI.create("ws://0.0.0.0:18080/ws");
      SimpleWampWebsocketListener server;

      try {
         server = new SimpleWampWebsocketListener(router, serverUri, null);
         server.start();
      } catch (Exception e) {
         e.printStackTrace();
         return;
      }

      //server.stop();
   }
}
