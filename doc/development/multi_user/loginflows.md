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

_Tip: To edit the diagram, replace `/svg/` with `/uml/` in the image URL._

## `auth_type = "config-file"`

With this configuration the Krill `GET /auth/login` REST API endpoint responds with `/login?withId=true`. The same internal login form is shown as with `auth_type = "admin-token"` but with two differences:

1. A hidden additional login field for the user ID is revealed. This allows the user to enter a username and password pair.
2. The entered password is not sent as-is in the bearer token, instead it is hashed using the `scrypt` algorithm and a salt based in part on the entered login ID and the hash is sent as the bearer token.

## `auth_type = "openid-connect"`

With OpenID Connect the flow is different:

![PlantUML Diagram](http://www.plantuml.com/plantuml/svg/bLJTRnj547-_ls9Ka0KFFaSjui7okGMxG24qfdP1aIn5SxVJyvAztMDtpetvwzaFdrq7DqbValFiVFm-PlULOxJSDIhRI47mmHWkpLsMjJugAzcYPhZ4slYqazYFrdnqP4zYlrcfr4dagYNzPZupMbF52sksKlYQh2XWJaosaPg0DmJAr5BxuRO1DY2aQnNke2YoR3yRXjFK7iRmy-iLZB3ZpIYM7L8cmqFAXhbruz5eSkMdGpyOBkEO1TO4xzzTJb_wAgPYkLmEB0bfgUARpieYLKzIiv_-cB-Tfd4LAbLYTHi9l7TaGJf8TIG2SDG2N5SsabsazS8A27BizWHROndLFLwzb1xsMzpA6fc0JQoFwDiU_L6ah2_nrMSbJYezKOQrtWjnVNszrbyenHEGBACYv-1FXfyjUhT74QH8qyDSO-M_oD9e82rQ8pNtlSulI0_pPMK45RFPR72mVAsNnCEPCRUInf3dUNGrjQ2xQeEwfkIYfOhaDZXCJMiisjqzBA5v80O8bb01crlIqUNOxY5j5bTBZtKIAuOzf-18RL7p3UzQAaw6tOHXtgMUqAbXwd73uib3ol_wrmf-g2foBkxpcpci8XzBhZNQKK_ggFVloDK6AeMoWGRRLkeQRAV80TOejUFOCvqBPFpK_xx7BwlL0bvSF8UHr8BkyWqtwgjqmRqQKPzYKgAZxxy3qe6zI3fxiGPI59CktaSHVYApbMN7vFvN4hEEvzDpwzE7FXYb_5VQWVlh-5aEpoykuYRzsL7-jmDh_1oR_hd-NZ-BD_0PR2LzZ7k2Yk6rjSQEuHj1d1wKSkUJfSk_ZiNvFntPNKuX2qeA6ZlYRpE0urFIV_gzGkie-jS_fdxkMXzMERLfo3ciAIFb29PTDFrH15B0O70c7jquVtGK752fnz279uED_VJYnTPX4ygzwifKgC3vDAmZpxLcKgfNdKrIF7oCCj8YU-N_T8tw3m00)

_Tip: To edit the diagram, replace `/svg/` with `/uml/` in the image URL._

The parts of this flow that involve Krill can be diagnosed by increasing the Krill log level to debug or trace.

The parts of this flow that happen between the browser and the 3rd party OpenID Connect Provider will not be visible in the Krill logs. Instead you will need to monitor the requests and responses in the browser, e.g. using the Google Chrome Developer Tools Network tab.
