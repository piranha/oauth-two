(require '[clojure.edn :as edn])

(def +deps+ (-> "deps.edn" slurp edn/read-string))

(defn deps->vec [deps]
  (vec (keep (fn [[dep {:keys [:mvn/version exclusions]}]]
               (when version ;; will skip deps.edn-based deps
                 (cond-> [dep version]
                   exclusions (conj :exclusions exclusions))))
            deps)))

(def dependencies (deps->vec (:deps +deps+)))

(defproject oauth/oauth.two "0.5.0-SNAPSHOT"
  :description "OAuth 2.0 in Clojure"
  :url "https://github.com/jcf/oauth-two"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies ~dependencies)
