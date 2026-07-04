- Making victim's browser do unintentional actions.
- 3 conditions need to be met:
(i) A relevant action
(ii) cookie-based session handling
(iii) No unpredictable request parameters

- Common defenses:
(i) CSRF Tokens:makes every req unique
(ii) Samesite cookies: makes sure if a website's cookies are included in req originating from other websites.
(iii) Referer-based validation: verifies if req originated from application's same domain.

- CSRF validation flaws:
(i) Applications validate CSRF tokens at POST req; can skip it if using changing req method to GET [don't give any method in payload -> direct GET req]
(ii) Remove the validation field itself
(iii) CSRF token isn't attached to the user's session [obtain the session token and use it for the request]
(iv) CSRF token is tied to a non-session cookie; exploitable if attacker can set a cookie and a valid token on the victim's browser [csrfKey and csrf]
(v) CSRF token is simply duplicated

- ORIGIN = Scheme + Hostname + Port
- SITE = Scheme + eTLD + 1
- Set-Cookie: allows to change cookies and tokens.
- SameSite policies:
(i) Strict: doesn't send any crosssite req
(ii) Lax: browser will send the cookie in cross site req if:
          (a) req uses GET method
          (b) req from a top-level navigation by the user such as clicking on a link
(iii) None: No restrictions for the SameSite attribute. When changing to None include Secure attribute so that the browser doesn't reject the cookie

- By default, browser's use Lax SameSite policy if not explicitly specified.
- Use document.location js method to invoke a desirable action while using GET req
- Use "_method" in <input> tag to put forward a req inside a req which overrides the <form> tag's req
- use "_method" in URL (way better).
- If SameSite=Strict, use any client side redirect mechanism the website has to do the intended action.
- If a site supports websickets, it can be vulnerable to cross-site websocket  hijacking(CSWSH) which is CSRF targetting a websocket handshake.
- If no SameSite found, Lax is applied after 120 seconds on top-level POST requests.
- Alternatively, you can trigger the cookie refresh from a newtab; browser doesn't leave the page till the final attack is delivered.
  EG:
  ```
  window.open('https://vuln.com.login/sso');
  ```
  Use onclick() to  bypass the browser flagging the request.
- Referer validation bypass:
  Remove it's presence:
  <meta name="Referer"
  content = "never">
