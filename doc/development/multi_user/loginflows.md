# Multi-User Feature: Login Flows

The HTTP request-response flow when logging in to the Krill web UI (aka Lagosta) is quite involved when using OpenID Connect. The logic within Lagosta also became more complex with the addition of multi-user support as it has to ensure that it shows the appropriate login form or redirects to an external form (e.g. for OIDC) and has to handle the different ways it is returned to at the end of the login process and the different kinds of error that can occur.

While you can in theory work out these flows by looking at the code and by capturing requests and responses and inspecting logs it is not trivial and the details are easily forgotten if you don't have to look at it for a while. To help with diagnosing issues and understanding the flow through the code this page tries to show visually how these processes work.

## Common behaviour

For all auth types, when Lagosta (in `router.js`) routes the user to the correct Vue.js "view",  it checks if the user is authorized using the Krill `GET /api/v1/authorized` REST API endpoint. If not they will be shown the login page that Krill reports via its `GET /auth/login` REST API endpoint. This will either be an externally hosted 3rd party login portal e.g. of an OpenID Connect provider, or a login Vue.js "view" internal to Lagosta. 

When making requests to the Krill REST API, a special browser-side Axios request handler function `authHeader()` checks for a `krill_user` value stored in browser local storage and if found injects an `Authorization: Bearer ${krill_user}` HTTP header into the request.

If the user is neither logged in according to Krill or Lagosta the login URL will be determined by calling the Krill REST API `GET /auth/login`. If the URL starts with `http` it is treated as an external login URL (e.g. an OpenID Connect provider login portal) to direct the browser to navigate to. Otherwise it is treated as the name of a login "view" internal to Lagosta that Vue.js should switch to.

## `auth_type = "admin-token"`

With this configuration the Krill `GET /auth/login` REST API endpoint responds with `/login` which causes the user to be shown the internal Lagosta login page which has existed in Krill since Krill first had a web UI. This login page challenges the user to provide the correct admin token. The approximate flow is thus:

![PlantUML Diagram](http://www.plantuml.com/plantuml/svg/TP51JyCm38Nl-HN-0sFtQPq60d40YKc3dNR9shSraCR8Te3nwsahMWPebyYAdz_td2pLl5Xkegj31Tepsuu_N57GDGpIX0Io6XJv45BRbeQCgGhw6lsHYiAvUtzWDK-J1Tr9Y95cT7lpI5EVhPxsOwDaFXabtvqEzAGGqhnhWcd76jnHzRnpaDN3-XTbcoxRcYLyUWkSPdG5Bn2Q8na45Hc_82rSFtzgj864_P449SBReFkNkOywNDO-LH5wyZAQonAgn49x7s8MzBbzjA7bY7ws6CePhOq5V-3KRRCJVbS8HIvz93KMVm2ru6qon4YRZ8jd9MCIpeQkc3f4nH3W373bHNkVyHUjnZQD2I32GWrKMvv3gjooFN8Jlm00)

## `auth_type = "config-file"`

With this configuration the Krill `GET /auth/login` REST API endpoint responds with `/login?withId=true`. The same internal login form is shown as with `auth_type = "admin-token"` but with two differences:

1. A hidden additional login field for the user ID is revealed. This allows the user to enter a username and password pair.
2. The entered password is not sent as-is in the bearer token, instead it is hashed using the `scrypt` algorithm and a salt based in part on the entered login ID and the hash is sent as the bearer token.

## `auth_type = "openid-connect"`

With OpenID Connect the flow is different:

![PlantUML Diagram](http://www.plantuml.com/plantuml/svg/dPHFJzjC4CRl_XHpufPmU6ye3ho5gcfB2-9F2v8bDB47PyjwrfeTKz9Ft_4wZX8AgEebSdPtdldDytXz51L5kyPdIrSHt8UWY_2KPQsjkjAro0gdM0SxjhFsJiBFIBApzbcSzpihPotnnvFZm4obdajuj1wIPNaE9wGaZMC2NHBuK3ksvjA01gXSR3sk8C-pRDqR9lD17WxWm_ihsCTEb_kfR7DaDjaScT6JoJDwkBuuXN2VcWmmiAQ14UTPSw7AYUsdaYwIsE8y8L_tVro4OP-g_ZHo1R5RD4vZAlXFAkWDMArLso2A_jaaeta6-XKVNOrAfhN5MF08sVu9cOtL9lIYluD5_-h1_6_qBzF8Bq1P2AyMNMoS3UkW-X23k5-eBZ0GLsrmhAFMovcNwFq2ouV3CbIKtzpSx4L5fVpszhRWIzB9SGWFZWvWEfscs0O9UYgNo3KDCHa6kSS-Gcei8fJLCvPUl1yC48JG6_83SOenoRtbpVdPfR7EKiLad6bUy64jo7gdgvRodMPtVRE2zyQ1x75y2UywyVbiQBaxVX_gV81vo_DFtw_W_xAa6DEhQj5VfKc4OXiuqg2mxVGNr789fKVNG8DjwxW6wJoPG8sEeoRDORz2nUtaHuqBqauOiC-qb5NRNvPe32xmu6GAPhmGIoCp_QqFGUm6v21mZyvtGibwz3fkPG1RzsdzQE-b1jbEDytgkE356j87Cn2Y7SEQUaiALZBcRnrDVyHq_qCtNCVzZ7oa4U2LXkSeCUbiFbesHS4R0X890eqHMx-CkCgExATh_6y0)