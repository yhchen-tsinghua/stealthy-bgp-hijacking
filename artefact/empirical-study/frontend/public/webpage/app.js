// Setup MiniSearch
const miniSearch = new MiniSearch({
    idField: "id",
    extractField: (doc, fieldName) => {
        if (Array.isArray(doc[fieldName])) {
            return doc[fieldName].join(" ");
        } else {
            return doc[fieldName];
        }
    },
    fields: ["prefixes", "expected_origins", "unexpected_origins"],
    tokenize: (text, _) =>
        text.split(/\s+/).map((str) => str.replace(/^[^\w]+|[^\w]+$/g, "")),
});

// Select DOM elements
const $app = document.querySelector(".App");
const $search = document.querySelector(".Search");
const $searchInput = document.querySelector(".Search input");
const $clearButton = document.querySelector(".Search button.clear");
const $reloadButton = document.querySelector(".Search button.reload");
const $resultList = document.querySelector(".ResultList");
const $suggestionList = document.querySelector(".SuggestionList");
const $options = document.querySelector(".AdvancedOptions form");
const $fromDate = document.getElementById("fromDate");
const $toDate = document.getElementById("toDate");
const $resultStats = document.querySelector(".ResultStats");

// Fetch and index data
$app.classList.add("loading");
let incidentById = {};
let alarmById = {};

fetch("all-alarms.json")
    .then((response) => response.json())
    .then((allAlarms) => {
        alarmById = allAlarms.reduce((byId, alarm) => {
            byId[alarm.id] = alarm;
            return byId;
        }, {});
    });

fetch("all-incidents.json")
    .then((response) => response.json())
    .then((allIncidents) => {
        incidentById = allIncidents.reduce((byId, incident) => {
            byId[incident.id] = incident;
            return byId;
        }, {});
        updateOptionFilters(allIncidents);
        updateSearchOptions();
        return miniSearch.addAll(allIncidents);
    })
    .then(() => {
        $app.classList.remove("loading");
        const results = getSearchResults(MiniSearch.wildcard);
        renderSearchResults(results, true);
    });

// Bind event listeners:

// Typing into search bar updates suggestions
$searchInput.addEventListener("input", (event) => {
    const query = $searchInput.value;
    const suggestions = getSuggestions(query);
    renderSuggestions(suggestions);
});

// Clicking on clear button clears search and suggestions
$clearButton.addEventListener("click", () => {
    $searchInput.value = "";
    $searchInput.focus();
    renderSuggestions([]);
});

// Clicking on reload button starts a search
$reloadButton.addEventListener("click", () => {
    const query = $searchInput.value;
    if (query.length > 0) {
        const results = getSearchResults(query);
        renderSearchResults(results, false);
    } else {
        const results = getSearchResults(MiniSearch.wildcard);
        renderSearchResults(results, true);
    }
});

// Clicking on a suggestion selects it
$suggestionList.addEventListener("click", (event) => {
    const $suggestion = event.target;

    if ($suggestion.classList.contains("Suggestion")) {
        const query = $suggestion.innerText.trim();
        $searchInput.value = query;
        $searchInput.focus();
        renderSuggestions([]);
    }
});

// Pressing up/down/enter key while on search bar navigates through suggestions
$search.addEventListener("keydown", (event) => {
    const key = event.key;

    if (key === "ArrowDown") {
        selectSuggestion(+1);
    } else if (key === "ArrowUp") {
        selectSuggestion(-1);
    } else if (key === "Escape") {
        $searchInput.blur();
        renderSuggestions([]);
    } else if (key === "Enter") {
        $searchInput.blur();
        renderSuggestions([]);

        const query = $searchInput.value;
        if (query.length > 0) {
            const results = getSearchResults(query);
            renderSearchResults(results, false);
        } else {
            const results = getSearchResults(MiniSearch.wildcard);
            renderSearchResults(results, true);
        }
    }
});

// Clicking outside of search bar clears suggestions
$app.addEventListener("click", (event) => {
    renderSuggestions([]);
});

const getSearchResults = (query) => {
    return miniSearch
        .search(query, searchOptions)
        .map(({ id }) => incidentById[id]);
};

const getSuggestions = (query) => {
    const queryTermCount = query.split(/\s+/).length;
    const suggestionOptions = { ...searchOptions, combineWith: "AND" };
    return (
        miniSearch
            .autoSuggest(query, suggestionOptions)
            .filter(
                ({ suggestion }) =>
                    suggestion.split(/\s+/).length <= queryTermCount
            )
            // .filter(({ suggestion, score }, _, [first]) => score > first.score / 4)
            .slice(0, 5)
    );
};

const tagStyleMap = {
    "WHOIS Recorded": "TagA",
    "Similar Org Name": "TagA",
    "Different Countries": "TagB",
    "Direct VP View": "TagB",
    "Origin Relay": "TagC",
    "Private-Use ASN": "TagC",
    "Origin AS-Set": "TagC",
};

const renderSearchResults = (results, showing_all) => {
    $resultList.innerHTML = results
        .map(
            ({
                id,
                time,
                prefixes,
                expected_origins,
                unexpected_origins,
                tags,
                category,
            }) => {
                const tagSpans = tags
                    .map(
                        (tag) =>
                            `<span class="Tag ${tagStyleMap[tag]}">${tag}</span>`
                    )
                    .join("\n");
                return `<li class="Result">
      <div class="ResultHeadline">
        <h3>#${id}</h3>
        <span class="ResultTime">${time}</span>
      </div>
      <dl>
        <dt>Category:</dt>
        <dd>
          ${category}
          ${tagSpans}
        </dd>
        <dt>Affected prefixes:</dt> <dd>${prefixes.join(", ")}</dd>
        <dt>Expected origins:</dt> <dd>${expected_origins.join(", ")}</dd>
        <dt>Unexpected origins:</dt> <dd>${unexpected_origins.join(", ")}</dd>
      </dl>
      <button class="details popup-trigger" popup-id="${id}">
        &#x2026;
        <span class="description">More</span>
      </button>
    </li>`;
            }
        )
        .join("\n");
    $resultStats.innerHTML = showing_all
        ? `showing all ${results.length} results.`
        : `${results.length} search results.`;
};

const renderSuggestions = (suggestions) => {
    $suggestionList.innerHTML = suggestions
        .map(({ suggestion }) => {
            return `<li class="Suggestion">${suggestion}</li>`;
        })
        .join("\n");

    if (suggestions.length > 0) {
        $app.classList.add("hasSuggestions");
    } else {
        $app.classList.remove("hasSuggestions");
    }
};

const selectSuggestion = (direction) => {
    const $suggestions = document.querySelectorAll(".Suggestion");
    const $selected = document.querySelector(".Suggestion.selected");
    const index = Array.from($suggestions).indexOf($selected);

    if (index > -1) {
        $suggestions[index].classList.remove("selected");
    }

    const nextIndex = Math.max(
        Math.min(index + direction, $suggestions.length - 1),
        0
    );
    $suggestions[nextIndex].classList.add("selected");
    $searchInput.value = $suggestions[nextIndex].innerText;
};

const updateOptionFilters = (allIncidents) => {
    if (allIncidents.length > 0) {
        const most_recent = allIncidents[0]["time"].split(" ")[0];
        const least_recent = allIncidents[allIncidents.length - 1][
            "time"
        ].split(" ")[0];
        $fromDate.min = least_recent;
        $fromDate.max = most_recent;
        $fromDate.value = least_recent;
        $toDate.min = least_recent;
        $toDate.max = most_recent;
        $toDate.value = most_recent;
    }
};

let searchOptions = {
    tokenize: (text, _) =>
        text.split(/\s+/).map((str) => str.replace(/^[^\w]+|[^\w]+$/g, "")),
};

const updateSearchOptions = () => {
    const formData = new FormData($options);

    searchOptions.fuzzy = formData.has("fuzzy") ? 0.2 : false;
    searchOptions.prefix = formData.has("prefix");
    searchOptions.fields = formData.getAll("fields");
    searchOptions.combineWith = formData.get("combineWith");

    const fromDate = formData.get("fromDate");
    const toDate = formData.get("toDate");
    const categorySet = new Set(formData.getAll("category"));
    const tagSet = new Set(formData.getAll("tags"));
    const noneIncluded = tagSet.has("(no tag)");

    searchOptions.filter = ({ id }) => {
        const { time, tags, category } = incidentById[id];
        const date = time.split(" ")[0];
        return (
            date >= fromDate &&
            date <= toDate &&
            categorySet.has(category) &&
            ((tags.length === 0 && noneIncluded) ||
                tags.some((tag) => tagSet.has(tag)))
        );
    };
};

// Changing any advanced option triggers updated options
$options.addEventListener("change", (event) => {
    updateSearchOptions();
});

const $popup = document.getElementById("popup");
const $popupTitle = document.getElementById("popup-title");
const $popupBody = document.getElementById("popup-body");
const $popupCloseButton = document.getElementById("popup-close-button");

// Function to show the popup
const showPopup = (title, content) => {
    $popupTitle.textContent = title;
    $popupBody.innerHTML = content;
    $popup.style.display = "flex";
};

// Function to close the popup
const closePopup = () => {
    $popup.style.display = "none";
};

// Event delegation: Handle clicks on elements with class 'popup-trigger'
$app.addEventListener("click", (event) => {
    if (event.target.classList.contains("popup-trigger")) {
        const popupId = event.target.getAttribute("popup-id");
        let title = "";
        let content = "";

        // Dynamically generate content based on the popup-id
        switch (popupId) {
            case "download":
                title = "Download";
                content = `<div class="popup-body-general">
<h3 id="incidents">Incidents</h3>
<p>All incidents keyed by ID in JSON format: ${downloadJSON(incidentById, "incidentById.json", "incidentById.json")}</p>
<pre class="hljs"><code><div>{
    &quot;0&quot;: {
        &quot;id&quot;: 0,
        &quot;time&quot;: &quot;2025-01-01 12:00&quot;,
        &quot;prefixes&quot;: [...],
        &quot;expected_origins&quot;: [...],
        &quot;unexpected_origins&quot;: [...],
        &quot;tags&quot;: [...],
        &quot;alarm_id&quot;: [...],
        &quot;category&quot;: &quot;Potential Stealthy Hijacking&quot;,
        &quot;ai_output&quot;: &quot;Unavailable for this incident.&quot;
    },
    ...
}
</div></code></pre>
<h3 id="alarms">Alarms</h3>
<p>All alarms keyed by ID in JSON format: ${downloadJSON(alarmById, "alarmById.json", "alarmById.json")}</p>
<pre class="hljs"><code><div>{
    &quot;20250101.1200.amsix_route-views2_wide.I#17.A#0&quot;: {
        &quot;alarm_trigger&quot;: {
            &quot;wide&quot;: [...],
            ...
        },
        &quot;risk_critical&quot;: [...],
        &quot;risk_observing&quot;: [...],
        &quot;risk_ignorant&quot;: [...],
        &quot;affected_prefixes&quot;: [...],
        &quot;mis_announced_prefixes&quot;: [...],
        &quot;expected_origins&quot;: [...],
        &quot;unexpected_origins&quot;: [...],
        &quot;expected_routes&quot;: [
            [
                &quot;165.21.112.0/21&quot;,
                &quot;1103 &lt;7473&gt; &lt;3758&gt; 9506&quot;,
                &quot;amsix.9917346&quot;
            ],
            ...
        ],
        &quot;organizations&quot;: {
            &quot;risk_critical&quot;: {
                &quot;3758&quot;: [
                    &quot;SINGNET&quot;,
                    &quot;SingNet Pte Ltd&quot;,
                    &quot;SG&quot;,
                    &quot;APNIC&quot;,
                    &quot;20230905&quot;
                ],
                ...
            },
            &quot;expected_origins&quot;: {
                &quot;9506&quot;: [
                    &quot;SINGTEL-FIBRE&quot;,
                    &quot;Singapore Telecommunications Ltd, Magix Services&quot;,
                    &quot;SG&quot;,
                    &quot;APNIC&quot;,
                    &quot;20230905&quot;
                ],
                ...
            },
            &quot;unexpected_origins&quot;: {
                &quot;64013&quot;: [
                    &quot;KDC-AS-AP&quot;,
                    &quot;CONA HOSTING SDN BHD&quot;,
                    &quot;KR&quot;,
                    &quot;APNIC&quot;,
                    &quot;20230905&quot;
                ],
                ...
            }
        },
        &quot;tags&quot;: [...],
        &quot;id&quot;: &quot;20250101.1200.amsix_route-views2_wide.I#17.A#0&quot;
    }
}
</div></code></pre>
</div>`;
                break;
            case "about":
                title = "About";
                content = `<div class="popup-body-general">
<h3 id="notation">Notation</h3>
<p>We represent each route in the format <code>{prefix}: {routing path}</code>. For example:</p>
<pre class="hljs"><code><div>115.117.0.0/16: 1103 3257 6453 4755 10199
</div></code></pre>
<p>In this notation:</p>
<ul>
<li>
<p>The rightmost (last) ASN in the routing path, e.g., <code>10199</code> in this case, is the origin AS, which announces the route and claims ownership of the prefix.</p>
</li>
<li>
<p>The leftmost (first) ASN, e.g., <code>1103</code>, is the vantage point (VP), which provides visibility into its routing table and is the source from which we obtain this route.</p>
</li>
</ul>
<p>At a high level, this example indicates that, according to AS <code>1103</code>, traffic destined for <code>115.117.0.0/16</code> should follow the routing path <code>3257 6453 4755</code> before reaching its final destination, the origin AS <code>10199</code>. Consequently, AS <code>1103</code> would forward traffic for <code>115.117.0.0/16</code> to its neighboring AS <code>3257</code>.</p>
<h3 id="stealthy-bgp-hijacking-in-partial-rov-deployment">Stealthy BGP Hijacking in Partial ROV Deployment</h3>
<p>Stealthy BGP hijacking occurs when an AS, despite being protected from malicious route announcements by ROV-enabled ASes, has its traffic diverted to a hijacker through legacy ASes (i.e., those that do not deploy ROV) along the data forwarding path. Consider the following example:</p>
<pre class="hljs"><code><div>115.117.0.0/16: A B C D E
115.117.55.0/24: C G H
</div></code></pre>
<p>Here, AS <code>E</code> is the legitimate origin of the <code>115.117.0.0/16</code> prefix. If AS <code>H</code> illegitimately announces the more specific <code>/24</code> prefix (<code>115.117.55.0/24</code>), ROV-enabled ASes should reject this announcement. In this scenario, only AS <code>B</code> enforces ROV, meaning that the vantage point <code>A</code> only observes the legitimate route (<code>A B C D E</code>) and does not receive the malicious route. However, AS <code>C</code>, which does not enforce ROV, accepts the illegitimate <code>/24</code> announcement (<code>C G H</code>).</p>
<p>As a result, AS <code>A</code> (and its downstream networks) believe that traffic destined for <code>115.117.0.0/16</code> will safely reach the legitimate origin AS <code>E</code> via the path <code>A B C D E</code>. However, in reality, a portion of traffic specifically destined for <code>115.117.55.0/24</code> will be forwarded towards the hijacker AS <code>H</code> due to AS <code>C</code>’s routing decision. This hijacking remains stealthy because AS <code>A</code> is unaware of the malicious route and cannot detect the hijack even by inspecting its routing table.</p>
<p>Furthermore, the malicious route may not always be directly observed at a vantage point but can be inferred through segmentation of routing paths. Consider the following example:</p>
<pre class="hljs"><code><div>115.117.0.0/16: A B C D E
115.117.55.0/24: I C G H
</div></code></pre>
<p>In this case, the <code>/24</code> route is not directly seen at AS <code>C</code> but can be inferred from the vantage point <code>I</code>, which observes the <code>/24</code> announcement (<code>I C G H</code>). This suggests that AS <code>C</code> also has a route to <code>115.117.55.0/24</code> originating from AS <code>H</code>, indicating potential stealthy hijacking similar to the previous scenario.</p>
<h3 id="general-pattern-of-stealthy-bgp-hijacking">General Pattern of Stealthy BGP Hijacking</h3>
<p>Stealthy hijacking generally follows this pattern:</p>
<pre class="hljs"><code><div>P1: V1, ..., X, ..., O1
P2: V2, ..., X, ..., O2
</div></code></pre>
<p>where:</p>
<ol>
<li><code>O1 ≠ O2</code> (i.e., the origins are different).</li>
<li><code>P2</code> is either equal to <code>P1</code> or a sub-prefix of <code>P1</code>.</li>
<li>The prefix-origin pair <code>(P2, O2)</code> is RPKI invalid, IRR conflicting, and WHOIS mismatching.</li>
<li><code>V1</code> has no route to <code>P2</code> that originates from <code>O2</code>.</li>
</ol>
<p>This pattern captures the essence of stealthy hijacking, where a malicious prefix announcement evades detection by leveraging ASes that do not enforce ROV, leading to unintended traffic redirection.</p>
<h3 id="bad-operational-practice-vs-potential-stealthy-hijacking">Bad Operational Practice vs. Potential Stealthy Hijacking</h3>
<p>Given the identified pattern of stealthy hijacking, certain sets of routes may exhibit characteristics consistent with a potential hijacking incident. However, distinguishing between an unintentional misconfiguration and a deliberate attack can be challenging.</p>
<p>To assess whether an incident results from bad operational practice rather than a malicious hijacking, we apply the following heuristics:</p>
<ul>
<li>There is any connection between the legitimate origin AS and the illegitimate origin AS, such as:
<ul>
<li>Both ASes belong to the same organization or have similar organizational names.</li>
<li>Their organizations have some form of partnership or business relationship.</li>
</ul>
</li>
<li>There are indications of route engineering, such as origin relaying.</li>
<li>The incident is long-lasting rather than a transient event.</li>
</ul>
<p>If any of these conditions hold, the observed route anomaly is more likely due to misconfiguration or suboptimal operational practices rather than an intentional attack.</p>
<p>Conversely, if none of these conditions apply and the two origin ASes differ significantly in terms of scale, geographic location, or operational characteristics, the event may indeed indicate a stealthy hijacking risk.</p>
<p>It is crucial to exercise extreme caution before labeling an incident as an actual hijacking. Even the slightest indication of bad operational practices should be sufficient to classify the event as non-malicious rather than an intentional attack.</p>
<h3 id="terms-explanation">Terms Explanation</h3>
<p>Fields in Alarms:</p>
<ul>
<li>
<p>Risk-critical ASes: This field identifies the set of Autonomous Systems (ASes) along the path that are responsible for forwarding traffic to unexpected origins. These ASes are flagged as critical based on control-plane observations from at least one vantage point, indicating their role in the potential risk highlighted by the alarm.</p>
</li>
<li>
<p>Risk-observing VPs: This field enumerates the vantage points that detected unexpected routes in their routing tables.</p>
</li>
<li>
<p>Risk-ignorant VPs: This field lists the vantage points that only observed expected routes and did not detect any unexpected routes in their routing tables.</p>
</li>
<li>
<p>Affected prefixes: This field specifies the set of prefixes that are at risk of being hijacked.</p>
</li>
<li>
<p>Mis-announced prefixes: This field lists the prefixes that were announced by illegitimate origins, which may indicate hijacking.</p>
</li>
<li>
<p>Expected origins: This field identifies the legitimate origins that are authorized to announce the affected prefixes.</p>
</li>
<li>
<p>Unexpected origins: This field lists the illegitimate origins that mis-announced the prefixes, potentially leading to hijacking.</p>
</li>
<li>
<p>Expected routes: This field contains the routes for the affected prefixes that were announced by legitimate origins. These routes are considered normal and show no signs of hijacking.</p>
</li>
<li>
<p>Unexpected routes: This field lists the routes for the affected prefixes that were mis-announced by illegitimate origins. These routes are indicative of actual hijacking.</p>
</li>
</ul>
<p>Signs of Routing Engineering:</p>
<ul>
<li>
<p>Origin Relay: The expected origin is also present on the unexpected route.</p>
</li>
<li>
<p>Private-Use ASN: The unexpected origin uses an ASN reserved for private use.</p>
</li>
<li>
<p>Origin AS-Set: The unexpected origin is an AS-set.</p>
</li>
<li>
<p>Similar Org Name: The expected and unexpected origins have organization names that are similar at the character level.</p>
</li>
<li>
<p>WHOIS Recorded: The unexpected origins and their associated organizations are documented in WHOIS records, and these records correspond to the affected prefixes.</p>
</li>
</ul>
<p>Other Tags:</p>
<ul>
<li>
<p>Direct VP View: A vantage point is also identified as a risk-critical AS.</p>
</li>
<li>
<p>Different Countries: The expected and unexpected origins are located in different countries.</p>
</li>
</ul></div>`;
                break;
            case "feedback":
                title = "Feedback";
                content = `<div class="popup-body-general">
<div class="iframe-container"><iframe src="https://docs.google.com/forms/d/e/1FAIpQLSeRAbK-FagrKUMsTOo72WHWuYTVxVa9jcXEXfb7P0ldd1zH-Q/viewform?embedded=true&usp=pp_url&entry.975013181=%5BIncident+ID%5D%0AThe+related+incident+is+%23XXX.%0A%0A%5BRelationship%5D%0AI'm+related+with+this+incident+in+a+way+that+...+/+I'm+not+related+with+the+incident.%0A%0A%5BFeedback%5D%0AI+believe+this+incident+is+...%0AMy+insights/suggestions+are+...&entry.1769203092=I+want+to+have+the+feature+that+...%0AThe+methodology+can+be+improved+by+...%0AYou+should+see+the+tool+at+..." class="responsive-iframe">Loading…</iframe></div>
</div>`;
                break;
            default:
                title = `Incident #${popupId}`;
                const {
                    time,
                    tags,
                    category,
                    prefixes,
                    expected_origins,
                    unexpected_origins,
                    alarm_id,
                    ai_output,
                } = incidentById[popupId];

                const generateRouteTable = (routes) => {
                    return (
                        `<div class="table-wrapper"><table>
                    <thead>
                    <tr>
                    <th>Prefix</th>
                    <th>Routing Path</th>
                    <th>Reference</th>
                    </tr>
                    </thead><tbody>` +
                        routes
                            .map(
                                (route) => `
                    <tr>
                    <td>${route[0]}</td>
                    <td>${route[1]}</td>
                    <td>${route[2]}</td>
                    </tr>
                    `
                            )
                            .join("") +
                        `</tbody></table></div>`
                    );
                };
                
                const generateOrgTable = (orgs) => {
                    return (
                        `<div class="table-wrapper"><table>
                    <thead>
                    <tr>
                    <th>Role</th>
                    <th>ASN</th>
                    <th>AS Name</th>
                    <th>Organization</th>
                    <th>Country</th>
                    <th>RIR</th>
                    <th>Last Updated</th>
                    </tr>
                    </thead><tbody>` +
                    Object.entries(orgs)
                    .map(([role, values]) => 
                        Object.entries(values)
                        .map(([asn, info]) => `<tr>
                        <td>${role.replace("_", "-").replace("origins", "origin")}</td>
                        <td>${asn}</td>
                        <td>${info[0]?info[0]:"/"}</td>
                        <td>${info[1]?info[1]:"/"}</td>
                        <td>${info[2]?info[2]:"/"}</td>
                        <td>${info[3]?info[3]:"/"}</td>
                        <td>${info[4]?info[4]:"/"}</td>
                        </tr>`).join("\n")
                    ).join("\n") +
                    `</tbody></table></div>`
                    );
                };

                const alarm_content = alarm_id
                    .map((id, index) => {
                        const {
                            alarm_trigger,
                            risk_critical,
                            risk_observing,
                            risk_ignorant,
                            affected_prefixes,
                            mis_announced_prefixes,
                            expected_origins,
                            unexpected_origins,
                            expected_routes,
                            unexpected_routes,
                            organizations,
                            tags,
                        } = alarmById[id];

                        const mergeKeyValue = (dict) =>
                            Object.entries(dict).map(
                                ([key, values]) =>
                                    `<li>${key}: ${values.join(", ")}</li>`
                            ).join("\n");

                        const tagSpans = tags.map((tag) =>
                            `<span class="Tag ${tagStyleMap[tag]}">${tag}</span>`
                            ).join("\n");

                        return `<div class="Headline"><h2>Alarm #${index}</h2>
                        ${tagSpans}</div>
                        <ul>
                        <li><strong>ID:</strong>
                          ${id}</li> 
                        <li><strong>Triggering announcement:</strong></li>
                          <ul>${mergeKeyValue(alarm_trigger)}</ul>
                        <li><strong>Risk-critical ASes:</strong>
                          ${risk_critical.join(", ")}</li> 
                        <li><strong>Risk-observing VPs:</strong>
                          ${risk_observing.join(", ")}</li>
                        <li><strong>Risk-ignorant VPs:</strong>
                          ${risk_ignorant.join(", ")}</li>
                        <li><strong>Affected prefixes:</strong>
                          ${affected_prefixes.join(", ")}</li>
                        <li><strong>Mis-announcend prefixes:</strong>
                          ${mis_announced_prefixes.join(", ")}</li>
                        <li><strong>Expected origins:</strong>
                          ${expected_origins.join(", ")}</li>
                        <li><strong>Unexpected origins:</strong>
                          ${unexpected_origins.join(", ")}</li>
                        <li><strong>Expected routes:</strong>
                          ${generateRouteTable(expected_routes)}</li>
                        <li><strong>Unexpected routes:</strong>
                          ${generateRouteTable(unexpected_routes)}</li>
                        <li><strong>AS information:</strong>
                          ${generateOrgTable(organizations)}</li>
                        </ul>`;
                    })
                    .join("\n");

                content = `<ul class="PopupList">
                  <li>
                    <dl>
                      <dt>Category:</dt> <dd>${category}</dd>
                      <dt>Time:</dt> <dd>${time}</dd>
                      <dt>Affected prefixes:</dt> <dd>${prefixes.join(
                          ", "
                      )}</dd>
                      <dt>Expected origins:</dt> <dd>${expected_origins.join(
                          ", "
                      )}</dd>
                      <dt>Unexpected origins:</dt> <dd>${unexpected_origins.join(
                          ", "
                      )}</dd>
                    </dl>
                    <details class="ai-output">
                      <summary>GPT Analysis (beta)</summary>
                      <div class="ai-output-content">${ai_output}</div>
                    </details>
                  </li>
                  ${alarm_content}
                </ul>`;
        }
        showPopup(title, content);
    }
});

// Close button click event
$popupCloseButton.addEventListener("click", closePopup);

// Close popup if clicking outside of the content box
$popup.addEventListener("click", (event) => {
    if (event.target === $popup) {
        closePopup();
    }
});

const downloadJSON = (data, filename, text) => {
    const jsonData = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonData], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    return `<a href=${url} download=${filename}>${text}</a>`;
};
