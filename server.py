"""
Cryptoscope is a blockchain explorer service that is built to mask the
wallet addresses for all transactions, except for your own transactions.
There is no guarantee that Cryptoscope will be able to mask all wallet
addresses accurately, as there may be instances where wallet addresses
are not properly detected due to unforeseen circumstances. It is important
to note that Cryptoscope is not responsible for any loss of privacy or
any other damages that may result from the use of our service.
"""

import sys
import tornado
import tornado.web
import tornado.autoreload
import logging
import toml
import asyncio
import subprocess
import python_jwt as jwt
import datetime
import json
from jwcrypto import jwk

# load global settings (and keep track in global)
with open("./settings.toml") as handle:
    settings = dict(toml.load(handle))


# base class used for all the implemented pages
class BasePage(tornado.web.RequestHandler):

    # overload prepare to ensure session cookie set
    async def prepare(self):
        if self.get_cookie("SESSION") is None:
            await self.set_session_cookie()

    # return current authentication username (or None)
    def get_authenticated_user(self):
        cookie = self.get_cookie("SESSION")
        if cookie is None:
            return None

        try:  # transform exceptions into None result
            jwt_key = jwk.JWK.from_password(settings["jwt_key"])
            _, claims = jwt.verify_jwt(cookie, jwt_key, ["HS256"])
            if not type(claims) is dict:
                raise Exception("Invalid JWT")
            return claims.get("username", None)
        except Exception:
            logging.exception("get_authenticated_user")
        return None

    # set current session cookie with optional username
    async def set_session_cookie(self, username=None):
        claims = {"application": "crypto"}
        if username:
            claims["username"] = username
        jwt_key = jwk.JWK.from_password(settings["jwt_key"])
        token = jwt.generate_jwt(claims, jwt_key, "HS256", datetime.timedelta(days=2))
        self.set_cookie("SESSION", token)

    # invoke the specified sandboxed backend operation
    async def invoke(self, command):
        result = await asyncio.create_subprocess_exec(
            *settings["executor"] + command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        try:
            await asyncio.wait_for(result.wait(), 5000)
        except asyncio.TimeoutError:
            result.kill()
            return False, "Timeout"

        stdout, stderr = await result.communicate()
        if result.returncode:
            return False, stderr.decode()
        return True, stdout.decode()


# route rendering the home screen (overview of currencies)
class HomePage(BasePage):
    async def get(self):
        success, data = await self.invoke(["sandbox/currency"])
        if not success: raise tornado.web.HTTPError(500, data)  # noqa
        return self.render("index.html", data=json.loads(data))


# route rendering details for a specific symbol/currency
class DetailsPage(BasePage):
    async def get(self):
        symbol = self.get_argument("symbol", None)
        if symbol is None:
            return self.redirect("/")

        success, data = await self.invoke(["sandbox/currency", symbol])
        if not success: raise tornado.web.HTTPError(500, data)  # noqa
        return self.render("details.html", data=json.loads(data))

    # retrieve transactions for the specified symbol
    async def post(self):
        symbol = self.get_argument("symbol", None)
        if symbol is None:
            return self.write({"status": "failure"})

        success, data = await self.invoke(["sandbox/transaction", f"filter-symbol:{symbol} convert-to-json"])
        if not success: return self.write({"status": "failure"})  # noqa
        return self.write(json.loads(data))


# route rendering the search operation result page
class SearchPage(BasePage):
    async def get(self):
        query = self.get_argument("query", "")

        # mask wallet information (except for own transactions)
        username = self.get_authenticated_user() or ""
        success, data = await self.invoke(["sandbox/transaction", f"{query} mask-wallet-except:{username} convert-to-json"])
        if not success: raise tornado.web.HTTPError(500, data)  # noqa
        return self.render("search.html", data=json.loads(data), query=query)


# route rendering/processing the authentication process
class LoginPage(BasePage):
    async def get(self):
        return self.render("login.html", error=self.get_argument("error", None))

    async def post(self):
        username = self.get_body_argument("username", None)
        password = self.get_body_argument("password", None)
        if username is None or password is None:
            return self.redirect("/login?error=1")

        # invoke the secured command in the sandbox
        success, _ = await self.invoke(["sandbox/login", username, password])
        if not success:  # redirect to login with failure message
            return self.redirect("/login?error=1")
        await self.set_session_cookie(username)
        return self.redirect("/account")


# route terminating the session and redirecting
class LogoutPage(BasePage):
    async def post(self):
        await self.set_session_cookie()
        return self.redirect("/")


# route rendering the (authenticated) account screen
class AccountPage(BasePage):
    async def get(self):
        username = self.get_authenticated_user()
        if username is None:
            return self.redirect("/login")

        # obtain basic account information via sandboxed command
        success, account_data = await self.invoke(["sandbox/account", username])
        if not success: raise tornado.web.HTTPError(500, account_data)  # noqa
        account_data = json.loads(account_data)

        # obtain currency/transaction data for the combined data
        success, currency_data = await self.invoke(["sandbox/currency"])
        if not success: raise tornado.web.HTTPError(500, currency_data)  # noqa
        success, transact_data = await self.invoke(["sandbox/transaction", f"filter-username:{username} convert-to-json"])
        if not success: raise tornado.web.HTTPError(500, transact_data)  # noqa

        # build the transactions-per-currency table for rendering
        overview_data = {x["symbol"] : 0 for x in json.loads(currency_data)["currencies"]}
        for transaction in json.loads(transact_data)["transactions"]:
            overview_data[transaction["symbol"]] += 1

        return self.render(
            "account.html",
            overview_data=json.dumps(overview_data),
            account_data=account_data)

    # retrieve transaction details for authenticated user
    async def post(self):
        username = self.get_body_argument("username", None)
        if username is None:
            return self.redirect("/login")

        # no need to mask since only includes authenticated user
        success, data = await self.invoke(["sandbox/transaction", f"filter-username:{username} convert-to-json"])
        if not success: return self.write({"status": "failure"})  # noqa
        return self.write(json.loads(data))


# main function entry point (starting event loop)
def main():
    logging.basicConfig(level=logging.INFO)
    logging.info("starting")

    application = tornado.web.Application(
        [
            (r"/", HomePage),
            (r"/detail", DetailsPage),
            (r"/login", LoginPage),
            (r"/account", AccountPage),
            (r"/search", SearchPage),
            (r"/logout", LogoutPage),
            (
                r"^/static/(.*)$",
                tornado.web.StaticFileHandler,
                {"path": r"static/"},
            ),

        ],
        **settings["tornado_settings"]
    )

    server = tornado.httpserver.HTTPServer(application)
    server.listen(settings["listen_port"])
    tornado.ioloop.IOLoop.instance().start()


# invoke main function and return rc
if __name__ == "__main__":
    sys.exit(main())
