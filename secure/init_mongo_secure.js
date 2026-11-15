// Inicialización del escenario ENDURECIDO.
// Se ejecuta una sola vez, con el usuario root, al crear el volumen de datos.
//  1) Usuario de aplicación con el mínimo privilegio: readWrite SOLO en "tienda"
//     (sin dbAdmin, sin userAdmin, sin acceso a otras bases de datos).
//  2) Contraseñas de los usuarios de la tienda almacenadas con bcrypt (coste 12).
//     Credenciales de laboratorio: alice / Alice#2026lab · bob / Bob#2026lab ·
//     admin / Adm1n#2026lab
//  3) Índice único en username y validación de esquema ($jsonSchema).
db = db.getSiblingDB("tienda");

db.createUser({
  user: process.env.MONGO_APP_USER,
  pwd: process.env.MONGO_APP_PASSWORD,
  roles: [{ role: "readWrite", db: "tienda" }],
  mechanisms: ["SCRAM-SHA-256"]
});

db.createCollection("usuarios", {
  validator: { $jsonSchema: {
    bsonType: "object",
    required: ["username", "password_hash", "rol"],
    additionalProperties: false,
    properties: {
      _id: {},
      username: { bsonType: "string", pattern: "^[A-Za-z0-9_.-]{3,32}$" },
      password_hash: { bsonType: "string", pattern: "^\\$2[aby]\\$" },
      rol: { enum: ["admin", "cliente"] },
      email: { bsonType: "string" }
    }
  } },
  validationAction: "error"
});
db.usuarios.createIndex({ username: 1 }, { unique: true });

db.usuarios.insertMany([
  { username: "admin", rol: "admin",   email: "admin@tienda.lab",
    password_hash: "$2b$12$Jh5TgE1MuVb115xfufnlHuxS.NfkbuD52EM4Ytl/iOLR0dp7u/x7e" },
  { username: "alice", rol: "cliente", email: "alice@tienda.lab",
    password_hash: "$2b$12$RR9xXIPu3XJBqDyv2nmV/OPdcYduwufqraTf2.yQDcpeJbp8.9b.K" },
  { username: "bob",   rol: "cliente", email: "bob@tienda.lab",
    password_hash: "$2b$12$ThKt6jwOcLG.lUNWq9KByuk/te6U6eAzygyhDSU42D8KhWiF5Ejti" }
]);

db.createCollection("pedidos", {
  validator: { $jsonSchema: {
    bsonType: "object",
    required: ["usuario", "producto", "cantidad"],
    properties: {
      usuario:  { bsonType: "string" },
      producto: { bsonType: "string", maxLength: 80 },
      cantidad: { bsonType: ["int", "long"], minimum: 1, maximum: 1000 },
      importe:  { bsonType: ["double", "int"] }
    }
  } }
});
db.pedidos.insertMany([
  { usuario: "alice", producto: "Portátil 14\"",     cantidad: 1, importe: 899.0 },
  { usuario: "alice", producto: "Ratón inalámbrico", cantidad: 2, importe: 39.8 },
  { usuario: "bob",   producto: "Monitor 27\"",      cantidad: 1, importe: 249.0 },
  { usuario: "bob",   producto: "Teclado mecánico",  cantidad: 1, importe: 79.9 }
]);

print("init_mongo_secure.js: usuario de aplicación y datos creados");
