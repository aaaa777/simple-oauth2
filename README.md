# about

this plugin enables to login with oauth account


# route jacking

this plugin overwrites two of routes and templates

```py
url_for("auth.login") # -> /login
url_for("auth.register") # -> /register
```