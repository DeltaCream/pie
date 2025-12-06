# Making Pie

I wanted to name this project originally as "Pi", but I thought that  it would make me sound too much of a nerd so I decided to name it "Pie" instead.

Here's the process of making Pie, currently we are at the beginning phase.
1. For the server, I use axum, for its ease of use, yet surprising amount of flexibility and community support and adoption.
2. Running it, I connect to both a local PostgreSQL instance, as well as a remote instance of Supabase.
3. For the scripts, I use PostgreSQL, and while I can't decide a name for my database objects (namely, the database itself, the tablespace, and the schema), I will be potentially using the following naming conventions in the future:
    - Database: pie_db
    - Tablespace: pie_tablespace
    - Schema: pie_schema
For now, I am using "database", "tablespace", and "schema" as placeholders.
As for the user, I am using "cream".

## Cookies, Sessions, and JWT: Authentication and Authorization Shenanigans

Cookies, and Sessions were the old bread and butter that I was used to back when I was a Computer Science student. From what I can recall, cookies are small files that you store on your computer to help remember that you transacted with a website before, while sessions are a thing from the side of the server that allows to remember who you are and if you are worth trusting (access is granted while logged in, else you are booted out, for example).

Turns out, they are quite different from what I remembered, and cookies are used more for storing data in the browser (client), used for stuff like login status and preferences, while sessions store data on the server, which is necessary for storing temporary or sensitive information.

How does JWT fit in the picture? Well, based on [GeeksForGeeks](https://www.geeksforgeeks.org/javascript/difference-between-session-and-cookies/), JWTs are used for authentication and authorization, and are stored on the client side, but are signed by the server, so that the client can verify that the token is valid and has not been tampered with.

In addition, I think I want to implement JWT as a bearer token for use in API transactions (updating, creating, and deleting resources) which is pretty neat, as I will be uisng it in either HttpOnly, Secure, or SameSite, which has benefits against JavaScript access (HTTPOnly), for security (Secure, via HTTPS), and cross-site scripting and forgery attacks (SameSite).

After some research, I also encountered using Redis as a cache for JWT tokens, which can improve performance and scalability by reducing the load on the server and allowing for faster token validation. Additionally, Redis can be used as a distributed cache for storing frequently accessed data, which can further improve performance and scalability. That is some crazy amount of optimization just for "doing things right" with some good old cookies and sessions. But over-optimizing is my thing and we will figure things out along the way.

So for now, what I intend to do is to implement Redis (or more preferably, Valkey), to use it as a distributed cache session store. However, I will also implement a hybrid session token session that intends to use a short-lived access token (in the form of a JWT) and a long-lived refresh token that is stored in the server or as an HttpOnly cookie, in order to be able to revoke access, while still being relatively stateless in some aspects.

## Server and Database Information Disparity: What Needs To Be Shown And What Doesn't
