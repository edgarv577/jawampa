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

public enum RegisterFlags {
    /**
     * the registered procedure is called with the caller's sessionID as part of the call details object.
     */
	DiscloseCaller("disclose_caller", "true"),
	
	/**
	 * For sets of registrations registered using either 'roundrobin' or 'random', load balancing is performed across calls to the URI.
	 * 
	 * For 'roundrobin', callees are picked subsequently from the list of registrations (ordered by the order of registration), 
	 * with the picking looping back to the beginning of the list once the end has been reached.
	 */
	InvokeRoundRobin("invoke","roundrobin"),
	
	/**
	 * For 'random' a callee is picked randomly from the list of registrations for each call.
	 */
	InvokeRandom("invoke","random"),
	
	/**
	 * For sets of registrations registered using either 'first' or 'last', 
	 * the first respectively last callee on the current list of registrations (ordered by the order of registration) is called.
	 */
	InvokeFirst("invoke","first"),
	InvokeLast("invoke","last"),
	
	/**
	 * With 'single', the Dealer MUST fail all subsequent attempts to register a procedure for the URI while the registration remains in existence.
	 * If the option is not set, 'single' is applied as a default.
	 * 
	 * With the other values, the Dealer MUST fail all subsequent attempts to register a procedure for the URI where the value 
	 * for this option does not match that of the initial registration.
	 */
	InvokeSingle("invoke","single"),
	
	
	/**
	 * By default, Subscribers subscribe to topics with exact matching policy. 
	 * That is an event will only be dispatched to a Subscriber by the Broker if the topic published to (PUBLISH.Topic) exactly matches the topic subscribed to (SUBSCRIBE.Topic).
	 */
	MatchExact("match","exact"),
	
	/**
	 * Example
	 * 	[
	 * 		32,
	 * 		912873614,
	 * 		{
	 * 			"match": "prefix"
	 * 		},
	 * 		"com.myapp.topic.emergency"
	 * 	]
	 * When a prefix-matching policy is in place, any event with a topic that has SUBSCRIBE.
	 * Topic as a prefix will match the subscription, and potentially be delivered to Subscribers on the subscription.
	 * In the above example, events with PUBLISH.Topic
	 * 
	 * com.myapp.topic.emergency.11
	 * com.myapp.topic.emergency-low
	 * com.myapp.topic.emergency.category.severe
	 * com.myapp.topic.emergency
	 * will all apply for dispatching. An event with PUBLISH.Topic e.g. com.myapp.topic.emerge will not apply.
	 */
	MatchPrefix("match","prefix"),
	
	/**
	 * Example
	 *  [
	 * 		32,
	 * 		912873614,
	 * 		{
	 * 			"match": "wildcard"
	 * 		},
	 * 		"com.myapp..userevent"
	 * 	]
	 * In above subscription request, the 3rd URI component is empty, which signals a wildcard in that URI component position. 
	 * In this example, events with PUBLISH.Topic
	 * 
	 * com.myapp.foo.userevent
	 * com.myapp.bar.userevent
	 * com.myapp.a12.userevent
	 * will all apply for dispatching. Events with PUBLISH.Topic
	 * 
	 * com.myapp.foo.userevent.bar
	 * com.myapp.foo.user
	 * com.myapp2.foo.userevent
	 * will not apply for dispatching.
	 */
	MatchWildcard("match","wildcard");
	
	private final String key;
	private final String value;
	
	private RegisterFlags(String key, String value)	{
		this.key = key;
		this.value = value;
	}

	public String getKey() {
		return key;
	}

	public String getValue() {
		return value;
	}
}
