// Sandstorm - Personal Cloud Sandbox
// Copyright (c) 2021 Sandstorm Development Group, Inc. and contributors
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { Meteor } from "meteor/meteor";
import { Match, check } from "meteor/check";
import { Random } from "meteor/random";
import { Router } from "meteor/iron:router";
import { SHA256 } from "meteor/sha";

import { globalDb } from "/imports/db-deprecated.js";

interface NewApiTokenResult {
  token: string;
}
interface MemoizedNewApiToken {
  timestamp: number;
  promise: Promise<NewApiTokenResult>;
}
interface MemoizedNewApiTokenMap {
  [index: string]: MemoizedNewApiToken;
}

const memoizedNewApiToken: MemoizedNewApiTokenMap = {};
// Maps sha256(JSON.stringify(parameters)) -> {timestamp, promise}
//
// This memoizes calls to the Meteor method "newApiToken", so that multiple calls in rapid
// succession will not create multiple tokens. `parameters` above is an array containing the
// calls parameters in order (excluding the method name and callback), and `promise` is a promise
// for the result of the call.

interface PostMessageEvent {
  data: {
    renderTemplate: RenderTemplateCall;
  },
  source: Window;
  origin: string;
}
interface RenderTemplateCall {
  rpcId: string;
  template: string;
  petname: string;
  roleAssignment: {
    allAccess: null;
  };
  forSharing: boolean;
  clipboardButton: string;
  unauthenticated: object;
  clientapp: string;
}
interface SenderGrain {
  grainId: () => string;
  title: () => string;
}

function checkedRenderTemplateRpc (event: unknown, senderGrain: unknown): void {
  check(event, MessageEvent);
  const call: unknown = (event as MessageEvent).data.renderTemplate;
  const rpcId: string = (call as RenderTemplateCall).rpcId;

  try {
    check(call, {
      rpcId: String,
      template: String,
      petname: Match.Optional(String),
      roleAssignment: Match.Optional(globalDb.roleAssignmentPattern),
      forSharing: Match.Optional(Boolean),
      clipboardButton: Match.Optional(Match.OneOf(undefined, null, "left", "right")),
      unauthenticated: Match.Optional(Object),
      // Note: `unauthenticated` will be validated on the server. We just
      // pass it through here.
      clientapp: Match.Optional(Match.Where(function (clientapp) {
        check(clientapp, String);
        // rfc3986 specifies schemes as:
        // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        return clientapp.search(/[^a-zA-Z0-9+-.]/) === -1;
      })),
    });
  } catch (error) {
    event.source.postMessage({ rpcId: rpcId, error: error.toString() }, event.origin);
    return;
  }
  let checkedEvent: PostMessageEvent = event as PostMessageEvent;

  check(senderGrain, {
    grainId: Match.Where(function (grainId) {
      return typeof grainId == "function" && typeof grainId() == "string";
    }),
    title: Match.Where(function (title) {
      return typeof title == "function" && typeof title() == "string";
    }),
  });
  let checkedSenderGrain: SenderGrain = senderGrain;

  return renderTemplateRpc(checkedEvent, checkedSenderGrain);
}

function renderTemplateRpc (event: PostMessageEvent, senderGrain: SenderGrain): void {
  // Request creation of a single-use template with a privileged API token.
  // Why?  Apps should not be able to obtain capabilities-as-keys to
  // themselves directly, because those can be leaked through an arbitrary
  // bit stream or covert channel.  However, apps often need a way to provide
  // instructions to users to copy/paste with some privileged token contained
  // within.  By providing this templating in the platform, we can ensure
  // that the token is only visible to the shell's origin.
  const call = event.data.renderTemplate;
  const rpcId: string = call.rpcId;

  const template = call.template;
  let petname = "connected external app";
  if (call.petname) {
    petname = call.petname;
  }

  let assignment = { allAccess: null };
  const clipboardButton = call.clipboardButton;
  if (call.roleAssignment) {
    assignment = call.roleAssignment;
  }

  const forSharing = call.forSharing ? call.forSharing : false;
  // Tokens expire by default in 5 minutes from generation date
  const selfDestructDuration = 5 * 60 * 1000;

  let clientapp = call.clientapp;
  if (clientapp) {
    clientapp = clientapp.toLowerCase();
  }

  let provider;
  if (Router.current().route.getName() === "shared") {
    provider = { rawParentToken: Router.current().params.token };
  } else {
    provider = { accountId: Meteor.userId() };
  }

  const owner = {
    webkey: {
      forSharing: forSharing,
      expiresIfUnusedDuration: selfDestructDuration,
    },
  };

  const params = [
    provider, senderGrain.grainId(), petname, assignment, owner, call.unauthenticated,
  ];

  const memoizeKey = SHA256(JSON.stringify(params));
  let memoizeResult: MemoizedNewApiToken | undefined = memoizedNewApiToken[memoizeKey];
  if (memoizeResult && (Date.now() - memoizeResult.timestamp > selfDestructDuration / 2)) {
    // Memoized result is too old. Discard.
    memoizeResult = undefined;
  }

  if (!memoizeResult) {
    memoizedNewApiToken[memoizeKey] = memoizeResult = {
      timestamp: Date.now(),
      promise: new Promise(function (resolve, reject) {
        const callback = (err: unknown, result: unknown) => {
          if (err) {
            reject(err);
          } else {
            check(result, {token: String});
            resolve(result as NewApiTokenResult);
          }
        };

        Meteor.call.apply(Meteor, ["newApiToken"].concat(params, callback));
      }),
    };
  }

  memoizeResult.promise.then((result: NewApiTokenResult) => {
    const tokenId = result.token;
    // Generate random key id2.
    const id2 = Random.secret();
    // Store apitoken id1 and template in session storage in the offer
    // template namespace under key id2.
    const key = "offerTemplate" + id2;
    const host = globalDb.makeApiHost(tokenId);
    const grain = senderGrain;
    const grainTitle = grain.title();
    // grainTitleSlug is the grain title with url-unsafe characters replaced
    let grainTitleSlug = grainTitle.toLowerCase().trim();
    grainTitleSlug = grainTitleSlug.replace(/\s+/g, "-")
                                   .replace(/[^\w-]+/g, "")
                                   .replace(/--+/g, "-")
                                   .replace(/^-+/, "")
                                   .replace(/-+$/, "");
    const renderedTemplate = template.replace(/\$API_TOKEN/g, tokenId)
                                     .replace(/\$API_HOST/g, host)
                                     .replace(/\$GRAIN_TITLE_SLUG/g, grainTitleSlug);
    let link = undefined;
    if (clientapp) {
      link = `clientapp-${clientapp}:${window.location.protocol}//${host}#${tokenId}`;
    }

    sessionStorage.setItem(key, JSON.stringify({
        token: tokenId,
        renderedTemplate: renderedTemplate,
        clipboardButton: clipboardButton,
        expires: Date.now() + selfDestructDuration,
        host,
        link,
      })
    );

    // Send message to event.source with URL containing id2
    // TODO(someday): Send back the tabId that requests to this token will use? Could be
    //   useful.
    const templateLink = window.location.origin + "/offer-template.html#" + id2;
    event.source.postMessage({ rpcId: rpcId, uri: templateLink }, event.origin);
  }, (error) => {
    event.source.postMessage({ rpcId: rpcId, error: error.toString() }, event.origin);
  });
}

export { checkedRenderTemplateRpc };
