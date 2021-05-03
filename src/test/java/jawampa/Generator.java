/*
 * Copyright 2014 Matthias Einwag
 *
 * The jawampa authors license this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package jawampa;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.TimeUnit;

import rx.Subscription;
import rx.functions.Action0;
import rx.functions.Action1;
import rx.schedulers.Schedulers;
import jawampa.connection.IWampConnectorProvider;
import jawampa.transport.netty.NettyWampClientConnectorProvider;
import jawampa.transport.netty.SimpleWampWebsocketListener;

public class Generator {

    Subscription addProcSubscription;
    Subscription eventPublication;
    Subscription eventSubscription;
    
    static final int eventInterval = 2000;
    int lastEventValue = 0;
    
    public void start() {
                
        URI serverUri = URI.create("ws://127.0.0.1:18080/ws");
        SimpleWampWebsocketListener server;

        IWampConnectorProvider connectorProvider = new NettyWampClientConnectorProvider();
        WampClientBuilder builder = new WampClientBuilder();

        // Build two clients
        final WampClient client1;
        final WampClient client2;
        try {            
            builder.withConnectorProvider(connectorProvider)
                   .withUri("ws://127.0.0.1:18080/ws")
                   .withRealm("com.magenta.test")
                   .withInfiniteReconnects()
                   .withReconnectInterval(3, TimeUnit.SECONDS);
            client1 = builder.build();
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
                    addProcSubscription = client1.registerProcedure("com.example.add").subscribe(new Action1<Request>() {
                        @Override
                        public void call(Request request) {
                            if (request.arguments() == null || request.arguments().size() != 2
                             || !request.arguments().get(0).canConvertToLong()
                             || !request.arguments().get(1).canConvertToLong())
                            {
                                try {
                                    request.replyError(new ApplicationError(ApplicationError.INVALID_PARAMETER));
                                } catch (ApplicationError e) {
                                    e.printStackTrace();
                                }
                            }
                            else {
                                long a = request.arguments().get(0).asLong();
                                long b = request.arguments().get(1).asLong();
                                request.reply(a + b);
                            }
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

        client1.open();

        eventPublication = Schedulers.computation().createWorker().schedulePeriodically(new Action0() {
            @Override
            public void call() {
                client1.publish("com.myapp.hello", lastEventValue);
                lastEventValue++;
            }
        }, eventInterval, eventInterval, TimeUnit.MILLISECONDS);
        
        waitUntilKeypressed();
        System.out.println("Stopping subscription");
        if (eventSubscription != null)
            eventSubscription.unsubscribe();
        
        waitUntilKeypressed();
        System.out.println("Stopping publication");
        eventPublication.unsubscribe();
                
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
