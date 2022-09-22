package jawampa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import jawampa.auth.client.Password;
import jawampa.auth.client.Ticket;
import jawampa.connection.IWampConnectorProvider;
import jawampa.transport.netty.NettyWampClientConnectorProvider;
import jawampa.transport.netty.NettyWampConnectionConfig;
import jawampa.transport.netty.SimpleWampWebsocketListener;
import rx.Observable;
import rx.Subscription;
import rx.functions.Action0;
import rx.functions.Action1;
import rx.schedulers.Schedulers;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.TimeUnit;

public class ClientTest {

   public static void main(String[] args) {
      new ClientTest().start();
   }

   Subscription addProcSubscription;
   Subscription eventPublication;
   Subscription eventSubscription;

   static final int eventInterval = 2000;
   int lastEventValue = 0;

   public void start() {

      IWampConnectorProvider connectorProvider = new NettyWampClientConnectorProvider();
      WampClientBuilder builder = new WampClientBuilder();

      // Build two clients
      final WampClient client1;
      try {

         builder.withConnectorProvider(connectorProvider)
                 .withUri("ws://127.0.0.1:18080/ws")
                 .withRealm("com.magenta.test")
                 .withAuthId("DDApdSyBYaBcCeqZBX4zf7d3nKC5tDzd")
                 //.withAuthMethod(new Ticket("NxbbTJvWDxDcN3BRJCC63HJQ39WrkbCE"))
                 .withAuthMethod(new Password("NxbbTJvWDxDcN3BRJCC63HJQ39WrkbCE"))
                 .withInfiniteReconnects()
                 .withReconnectInterval(5, TimeUnit.SECONDS)
                 .withConnectionConfiguration((new NettyWampConnectionConfig.Builder()).build());

         client1 = builder.build();
         client1.open();
      } catch (Exception e) {
         e.printStackTrace();
         return;
      }

      client1.statusChanged().subscribe(new Action1<WampClient.State>() {
         @Override
         public void call(WampClient.State t1) {
            System.out.println("Session1 status changed to " + t1);

            if (t1 instanceof WampClient.ConnectedState) {
               // Register a procedure

               ObjectMapper mapper = new ObjectMapper();
               ArrayNode id = mapper.createArrayNode();

               String kwarg = "{\"security\":" +
                       "         {          " +
                       "         \"authid\":\"bismark.vasquez@leapsight.com\"," +
                       "         \"client_id\":\"ycw3aqqazrn9flgrebdxquhewr8b6v2v\"," +
                       "         \"groups\": [\"business_account_admin\",\"resource_owners\"]," +
                       "         \"locale\": \"es_AR\"," +
                       "         \"meta\":" +
                       "            {" +
                       "            \"account_id\":\"mrn:account:business:5bb69d77-3fa9-4cbb-829b-09457a12ac3e\"," +
                       "            \"business_account_id\":\"mrn:account:business:5bb69d77-3fa9-4cbb-829b-09457a12ac3e\"," +
                       "            \"business_user_id\":\"mrn:person:5f201f21-c29e-4eb7-aaae-68fa159f29dc\"," +
                       "            \"user_id\":\"mrn:person:5f201f21-c29e-4eb7-aaae-68fa159f29dc\"" +
                       "            }," +
                       "         \"realm_uri\": \"com.magenta.test\", " +
                       "         \"session\": 7466872937963856, " +
                       "         \"username\":\"bismark.vasquez@leapsight.com\"}" +
                       "      }";

               id.add("mrn:agent:9099ac5e-12fd-4c46-b3a0-801099c16759");
               id.add(kwarg);

               Observable<String> result1 = client1.call("com.magenta.notification.fetch", String.class, id);
               result1.subscribe(new Action1<String>() {
                  @Override
                  public void call(String t1) {
                     System.out.println("Completed add with result: " + t1);
                  }
               }, new Action1<Throwable>() {
                  @Override
                  public void call(Throwable t1) {
                     System.out.println("Completed add with error: " + t1);
                  }
               });

            }
         }
      }, new Action1<Throwable>() {
         @Override
         public void call(Throwable t) {
            System.out.println("Session1 ended with error " + t);
         }
      }, new Action0() {
         @Override
         public void call() {
            System.out.println("Session1 ended normally");
         }
      });

      waitUntilKeypressed();
      System.out.println("Closing the client 1");
      client1.close().toBlocking().last();
   }

   private void waitUntilKeypressed() {
      try {
         System.in.read();
         while (System.in.available() > 0) {
            System.in.read();
         }
      } catch (IOException e) {
         e.printStackTrace();
      }
   }
}
