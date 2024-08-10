(ns oauth.two
  (:require [clojure.string :as str]
            [ring.util.codec :as codec]))

(set! *warn-on-reflection* true)

(defn- remove-nils [m]
  (reduce-kv (fn [m k v]
               (if v m (dissoc m k)))
    m m))

;;; Client

(defrecord Client [access-uri authorize-uri id secret redirect-uri scope])

(defn make-client
  "A simple record of a provider configuration. `config` is a map of:

  - `:access-uri` - URI returning access tokens
  - `:authorize-uri` - URI to redirect users where they can accept authorization
  - `:id` - client id/client key
  - `:secret` - client secret
  - `:redirect-uri` - (optional) our own uri where we await the user
  - `:scope` - (optional) if provider needs scope defined"
  ^Client [config]
  (assert (and (:access-uri config) (:authorize-uri config)
               (:id config) (:secret config)))
  (map->Client config))

;;; Authorization URL

(defn- join-scope [scope]
  (some->> scope sort (str/join " ")))

(defn authorization-url
  "Generate authorization URL to redirect user to. Arguments:

  - `client` - a client record (create with `make-client`)
  - `params` - (optional) a map of:
    - `:redirect-uri` - (optional) our own uri where we await the user
    - `:scope` - (optional) scope, if provider needs it to be defined
    - `:state` - (optional) if you want to pass state across login calls
  - `more` - (optional) - an arbitrary map of values to put in query string,
             like Google's `prompt` parameter."
  ([client]        (authorization-url client {}     {}))
  ([client params] (authorization-url client params {}))
  ([^Client client params more]
   (str (:authorize-uri client)
     "?"
     (-> (merge
           more
           {"client_id"     (:id client)
            "redirect_uri"  (or (:redirect-uri params) (:redirect-uri client))
            "response_type" "code"
            "scope"         (join-scope (or (:scope params) (:scope client)))
            "state"         (:state params)})
         remove-nils
         codec/form-encode))))

;;; Access token request

(defn- basic-auth
  [id secret]
  (when id
    (codec/base64-encode (.getBytes (str id ":" secret) "UTF-8"))))

(defn access-token-request
  "Generate a request map for `clj-http` to exchange an authorization code for
   an access token. Arguments:

  - `client` - a client record (create with `make-client`)
  - `params` - a map of:
    - `:code` - an authorization code from the provider
    - `:redirect-uri` - (optional) our own uri where we await the user
    - `:extra-body` - (optional) an arbitrary map of values to put in a request
                      body (remember it's form-encoded, not JSON)

  Providers return custom reponses to that request, you have to write handling
  code for each separately."
  [^Client client params]
  (assert (:code params))
  (let [basic (basic-auth (:id client) (:secret client))]
    {:request-method :post
     :url            (:access-uri client)
     :headers        (remove-nils
                       {"content-type"  "application/x-www-form-urlencoded"
                        "authorization" (some->> basic (str "Basic "))})
     :body           (-> {"client_id"    (:id client)
                          "code"         (:code params)
                          "grant_type"   "authorization_code"
                          "redirect_uri" (or (:redirect-uri params)
                                             (:redirect-uri client))}
                         (into (:extra-body params))
                         remove-nils
                         codec/form-encode)}))
