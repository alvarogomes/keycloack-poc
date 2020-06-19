const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const Keycloak = require('keycloak-connect');
const cors = require('cors');
const {Issuer} = require('openid-client');
const KcAdminClient = require('keycloak-admin').default;

const memoryStore = new session.MemoryStore();

const keycloak = new Keycloak({
    store: memoryStore
});


const app = express();
app.use(bodyParser.json());

// Enable CORS support
app.use(cors());

const sessionSettings = {
    secret: '123456',
    resave: false,
    saveUninitialized: true,
    store: memoryStore,
    cookie: {
        secure: false,
    }
}


app.use(session(sessionSettings));
app.use(keycloak.middleware());

const keycloakAdmin = new KcAdminClient({
    'baseUrl': keycloak.getConfig()["authServerUrl"],
    'realmName': keycloak.getConfig()["realm"]
});

// Authorize with admin users... or user that can create users...
(async () => {
    await keycloakAdmin.auth({
        username: 'admin',
        password: 'admin',
        grantType: 'password',
        clientId: 'admin-cli',
    });
})()


let clientKeycloak = {};

(async () => {
    const keycloakIssuer = await Issuer.discover(keycloak.getConfig()["realmUrl"]);
    clientKeycloak = new keycloakIssuer.Client({
        client_id: keycloak.getConfig()["clientId"],
        client_secret: keycloak.getConfig()["secret"]
    });

})()


app.post('/login', function (req, res) {

    (async () => {
        const tokenSet = await clientKeycloak.grant({
            grant_type: 'password',
            username: req.body.username,
            password: req.body.password,
        });
        res.json(tokenSet);
    })()
});


app.post('/signup', function (req, res) {

    (async () => {

        const user = await keycloakAdmin.users.create({
            realm: req.body.realm,
            username: req.body.username,
            email: req.body.email,
            enabled: true,
            emailVerified: true,
        });

        await keycloakAdmin.users.resetPassword({
            id: user.id,
            credential: {
                temporary: false,
                type: 'password',
                value: req.body.password,
            },
        });

        const role = await keycloakAdmin.clients.findRole({
            id: keycloak.getConfig()["clientId"],
            roleName: req.body.role
        });

        if (role != null) {
            await keycloakAdmin.users.addRealmRoleMappings({
                id: user.id,
                roles: [
                    {
                        id: role.id,
                        name: role.name,
                    },
                ],
            });
        }

        res.json({
            status: "0",
            message: "User created with success."
        });

    })().catch(reason => {
        res.status(400).json({error: reason.message});
    })

});

app.get('/unsecured_api', function (req, res) {
    res.json({message: 'not secure'});
});

app.get('/secured_api', keycloak.protect(), function (req, res) {
    res.json({message: 'secured'});
});

app.listen(3000, function () {
    console.log('Started at port 3000');
});

