# Mini_Blog

This repo contains simple CRUD apis for a mini_blog w/ authentication

## Pre-requisites
- Requires docker and docker-compose installed

## Steps to run
- Clone the repo
- Open terminal
- Change directory to root of repo
- Run command: ```docker-compose up --build```

## Possible Improvements:
- Changes to ```ormconfig.json``` file for running without docker i.e. local environment. This can be resolved w/ using environment variables and setting up paths in a config.ts file and setting TypeOrm configs while making a connection.
```
...
"entities": ["src/entities/**/*.ts"],
"migrations": ["src/migrations/**/*.ts"],
"subscribers": ["src/subscribers/**/*.ts"],
"cli": {
    "entitiesDir": "src/entities",
    "migrationsDir": "src/migrations",
    "subscribersDir": "src/subscribers"
}
```
- Move ```secretKey``` for JWT to environment variable and set up dynamically using ```dotenv``` and ```process.env```
- Shift database things to models
- Add some basic tests