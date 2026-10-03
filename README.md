# Juice Shop Login — Security Demo

A small login form, inspired by [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
built for a web-security assignment. It shows the **same login feature two ways** — a
**secure** version and a deliberately **vulnerable** one — so you can see exactly which
coding practice stops a SQL Injection or XSS attack.

## What it does

- An HTML + JavaScript login form (email + password).
- **Client-side validation** — blocks empty fields, requires `@` in the email, and
  requires a password of at least 8 characters.
- **Server-side validation** — the Node/Express server re-checks every request, so the
  rules still hold even if a client skips the browser (curl, Burp, fetch).
- A toggle between two server behaviors:
  - **Secure (default):** parameterized SQL queries, `bcrypt` password hashing, and HTML
    output encoding.
  - **Vulnerable (`--vuln`):** string-concatenated SQL and unescaped output, so the form
    can be exploited on purpose for the write-up.

> ⚠️ The vulnerable mode is intentionally insecure and is for local learning only.
> Never deploy it.

## Requirements

- [Node.js](https://nodejs.org/) 18 or newer (tested on Node 22)

## How to run

```bash
# 1. install dependencies
npm install

# 2a. run the SECURE version (default)
npm start

# 2b. OR run the VULNERABLE version (for the exploit demo)
npm run start:vuln
```

Then open <http://localhost:3000> in your browser.

### Seeded test accounts

| Email               | Password   |
| ------------------- | ---------- |
| `admin@juice-sh.op` | `admin123` |
| `jim@juice-sh.op`   | `ncc-1701` |

## Trying the attacks (vulnerable mode only)

Run `npm run start:vuln`, then in the login form:

- **SQL Injection (auth bypass):** email `admin@juice-sh.op'--`, password `anything1`.
  The `'--` comments out the password check and logs you in as admin.
- **Reflected XSS:** email `x@x.xx<img src=x onerror=alert('XSS')>`, password `anything1`.
  The raw input is echoed back and executed in the page.

Switch back to `npm start` (secure mode) and both attacks fail.

## Project structure

```
juice-shop-login-demo/
├── server.js            # Express server, SQLite, validation, secure/vulnerable logic
├── public/
│   ├── index.html       # the login form
│   ├── script.js        # client-side validation + fetch
│   └── style.css        # styling
├── package.json
└── README.md
```

## The fixes (secure mode)

| Attack        | Why it works in vulnerable mode      | Fix in secure mode                                  |
| ------------- | ------------------------------------ | --------------------------------------------------- |
| SQL Injection | input concatenated into the SQL      | **parameterized query** (`WHERE email = ?`)         |
| XSS           | raw input written to the page        | **output encoding** before rendering                |
| Weak auth     | passwords compared as a hash in SQL  | **bcrypt** salted hashing + generic error messages  |

## License

MIT — for educational use.
