# Making Pie

I wanted to name this project originally as "Pi", but I thought that it would make me sound too much of a nerd so I decided to name it "Pie" instead.

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

In addition, I think I want to implement JWT as a bearer token for use in API transactions (updating, creating, and deleting resources) which is pretty neat, as I will be using it in either HttpOnly, Secure, or SameSite, which has benefits against JavaScript access (HTTPOnly), for security (Secure, via HTTPS), and cross-site scripting and forgery attacks (SameSite).

After some research, I also encountered using Redis as a cache for JWT tokens, which can improve performance and scalability by reducing the load on the server and allowing for faster token validation. Additionally, Redis can be used as a distributed cache for storing frequently accessed data, which can further improve performance and scalability. That is some crazy amount of optimization just for "doing things right" with some good old cookies and sessions. But over-optimizing is my thing and we will figure things out along the way.

So for now, what I intend to do is to implement Redis (or more preferably, Valkey), to use it as a distributed cache session store. However, I will also implement a hybrid session token session that intends to use a short-lived access token (in the form of a JWT) and a long-lived refresh token that is stored in the server or as an HttpOnly cookie, in order to be able to revoke access, while still being relatively stateless in some aspects.

## Server and Database Information Disparity: What Needs To Be Shown And What Doesn't

A big problem that I've seen designing the backend is how things are represented in the server, through structs in Rust, and tables/views in Postgres. They are significantly different, because the differences in representation are due to how their position and purpose differs, though a lot of their data overlap.
For example, returning Postgres data usually involves raw data straight from the database, but Rust structs can be subject to intermediate data processing, which can lead to some of that raw data not being present in the final serialized outputs, or being transformed into a form unrecognizable from how it looks in the database. But most importantly aside from that conversation is that Rust structs must account for serialization and deserialization.

This is especially the case for inputs. Inputs deserialized as Rust structs may contain fields that never make it to the Postgres querying process, just as likely as it is that certain values returned from the querying process never make it out of the serialized output. 

## The UX Gift of Search Engines

Search engines aren't really a big thing in this application, and might be overkill, but it will serve as a great user experience to have a flashy-fast search engine that can return what users need faster than they can blink.

For this, I have encountered Meilisearch, which can be self-hosted. I have heard of other alternatives, like Sonic and most especially Algolia, but Algolia is hosted, and cannot be something that you use on your own, while Sonic is a bit minimal for my needs.

## Dual Core Servers

One of the defining features that I want to tackle when building this project is that there are two variants - one for Axum, and another for Actix Web. Both are powerful, both are popular. Building both in one project teaches me multiple things:

1. I can learn how to manage multiple projects in a single Git repository,
2. I can learn how to share common resources that these multiple projects use, and
3. I can learn both frameworks and increase my expertise on both, as well as increase the flexibility of my thinking between the two web frameworks.

How it works is that when you clone this repository, you can choose to build either of the two and have it running. This will eventually prove to be a big problem for me, but that's a problem I'm willing to tackle because I expect this project to be small to medium-sized only.

## Environs

You shouldn't commit your environment files (.env) and you should include it instead to the .gitignore file.

However, on Linux, there is a neat trick that we can use.

You can symlink the file so that you can have an .env file in this project, but you can have the original file be somewhere else.

In addition to adding the .env to the .gitignore file, this makes for a relatively distant, yet accessible .env that is secured by symlinking and prevention of committing to version history.

There might be some incompatibilities with this approach, but this section will be updated later on for when I encounter (and solve) those issues.
