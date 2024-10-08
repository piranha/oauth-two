(ns oauth.two-test
  (:require [clojure.test :refer [deftest testing is are]]
            [oauth.two :as two]
            [ring.util.codec :as codec]))

;; -----------------------------------------------------------------------------
;; Utils

(defn- parse-uri
  [^String url]
  (let [uri (java.net.URI. url)]
    {:authority (.getAuthority uri)
     :host      (.getHost uri)
     :path      (.getPath uri)
     :query     (.getQuery uri)
     :scheme    (.getScheme uri)}))

(defn- split-url
  [^String url]
  (let [{:keys [scheme host path query]} (parse-uri url)]
    [(str scheme "://" host path) (codec/form-decode query)]))

;; -----------------------------------------------------------------------------
;; make-client

(def ^:private test-client-config
  {:access-uri    "https://provider.example.com/token"
   :authorize-uri "https://provider.example.com/authorize"
   :id            "client-id"
   :secret        "client-secret"})

(deftest t-make-valid-client
  (are [conf] (two/make-client (merge test-client-config conf))
    {:redirect-uri "https://example.com/callback"}
    {:redirect-uri "https://example.com/callback"
     :scope        #{"read" "write"}}
    {:scope #{"read"}}
    {:scope #{"read" "write"}}))

;; -----------------------------------------------------------------------------
;; Authorization URL

(defn- make-test-client
  ([]  (make-test-client {}))
  ([m] (->> m (merge test-client-config) two/make-client)))

(def ^:private authorization-url-tests
  [{:desc   "with nothing more than a valid client"
    :client {}
    :params {}
    :query  {"client_id"     "client-id"
             "response_type" "code"}}

   {:desc   "with custom params"
    :client {}
    :params {}
    :more   {:approval_prompt "force"}
    :query  {"approval_prompt" "force"
             "client_id"       "client-id"
             "response_type"   "code"}}

   {:desc   "with a redirect-uri in the client"
    :client {:redirect-uri "https://client.example.com/callback"}
    :params {}
    :query  {"client_id"     "client-id"
             "redirect_uri"  "https://client.example.com/callback"
             "response_type" "code"}}

   {:desc   "when overriding the client redirect-uri with params"
    :client {:redirect-uri "https://client.example.com/callback"}
    :params {:redirect-uri "https://client.example.com/override/callback"}
    :query  {"client_id"     "client-id"
             "redirect_uri"  "https://client.example.com/override/callback"
             "response_type" "code"}}

   {:desc   "with scope in the client"
    :client {:scope #{"read" "write"}}
    :params {}
    :query  {"client_id"     "client-id"
             "response_type" "code"
             "scope"         "read write"}}

   {:desc   "when overriding the client scope with params"
    :client {:scope #{"read" "write"}}
    :params {:scope #{"override"}}
    :query  {"client_id"     "client-id"
             "response_type" "code"
             "scope"         "override"}}

   {:desc   "with some state"
    :client {}
    :params {:state "this does not change"}
    :query  {"client_id"     "client-id"
             "response_type" "code"
             "state"         "this does not change"}}])

(deftest t-authorization-url
  (doseq [{:keys [desc client more params query]} authorization-url-tests]
    (is (= query (-> (make-test-client client)
                     (two/authorization-url params more)
                     split-url
                     second))
        desc)))

;; -----------------------------------------------------------------------------
;; Access token request

(def ^:private access-token-request-tests
  [{:desc "with the default test client and a code"
    :client {}
    :params {:code "code"}
    :decoded-body {"client_id"  "client-id"
                   "code"       "code"
                   "grant_type" "authorization_code"}}

   {:desc   "with a redirect-uri in the client"
    :client {:redirect-uri "https://client.example.com/callback"}
    :params {:code "code"}
    :decoded-body
    {"client_id"  "client-id"
     "code"       "code"
     "grant_type" "authorization_code"
     "redirect_uri" "https://client.example.com/callback"}}


   {:desc   "when overriding the client redirect-uri with params"
    :client {:redirect-uri "https://client.example.com/callback"}
    :params {:code "code"
             :redirect-uri "https://client.example.com/override/callback"}
    :decoded-body
    {"client_id"    "client-id"
     "code"         "code"
     "grant_type"   "authorization_code"
     "redirect_uri" "https://client.example.com/override/callback"}}])

(deftest t-access-token-request
  (doseq [{:keys [desc decoded-body client params]} access-token-request-tests
          :let [{:keys [body headers request-method url]}
                (two/access-token-request (make-test-client client) params)]]
    (testing desc
      (is (= :post request-method))
      (is (= "https://provider.example.com/token" url))
      (is (= {"authorization" "Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ="
              "content-type"  "application/x-www-form-urlencoded"}
             headers))
      (is (= decoded-body (codec/form-decode body))))))
