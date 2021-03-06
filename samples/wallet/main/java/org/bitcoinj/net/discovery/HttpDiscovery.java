/*
 * Copyright 2014 Mike Hearn
 * Copyright 2015 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.net.discovery;

import com.google.common.annotations.*;
import com.google.protobuf.*;
import org.bitcoinj.core.*;
import org.slf4j.*;

import javax.annotation.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import static com.google.common.base.Preconditions.*;

/**
 * A class that knows how to read signed sets of seeds over HTTP, using a simple protobuf based protocol. See the
 * peerseeds.proto file for the definition, with a gzipped delimited SignedPeerSeeds being the root of the data.
 * This is not currently in use by the Bitcoin community, but rather, is here for experimentation.
 */
public class HttpDiscovery implements PeerDiscovery {
    private static final Logger log = LoggerFactory.getLogger(HttpDiscovery.class);

    public static class Details {
        @Nullable public final ECKey pubkey;
        public final URI uri;

        public Details(@Nullable ECKey pubkey, URI uri) {
            this.pubkey = pubkey;
            this.uri = uri;
        }
    }

    private final Details details;
    private final NetworkParameters params;
    private final OkHttpClient client;

    /**
     * Constructs a discovery object that will read data from the given HTTP[S] URI and, if a public key is provided,
     * will check the signature using that key.
     */
    public HttpDiscovery(NetworkParameters params, URI uri, @Nullable ECKey pubkey) {
        this(params, new Details(pubkey, uri));
    }

    /**
     * Constructs a discovery object that will read data from the given HTTP[S] URI and, if a public key is provided,
     * will check the signature using that key.
     */
    public HttpDiscovery(NetworkParameters params, Details details) {
        this(params, details, new OkHttpClient());
    }

    public HttpDiscovery(NetworkParameters params, Details details,  OkHttpClient client) {
        checkArgument(details.uri.getScheme().startsWith("http"));
        this.details = details;
        this.params = params;
        this.client = client;
    }

    @Override
    public List<InetSocketAddress> getPeers(long services, long timeoutValue, TimeUnit timeoutUnit) {
        return null;
    }

    @Override
    public void shutdown() {
    }
}
