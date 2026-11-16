// Carga idempotente de la base "tienda" en MongoDB Atlas (extensión cloud).
// Se ejecuta con el usuario de aplicación (readWrite solo sobre "tienda"), así que
// no crea usuarios: en Atlas los usuarios de BD se gestionan desde el panel.
// Contraseñas de la tienda con bcrypt (coste 12): alice / Alice#2026lab ·
// bob / Bob#2026lab · admin / Adm1n#2026lab
const t = db.getSiblingDB("tienda");
const existe = (n) => t.getCollectionNames().includes(n);

if (!existe("usuarios")) {
  t.createCollection("usuarios", {
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
  t.usuarios.createIndex({ username: 1 }, { unique: true });
}
if (t.usuarios.countDocuments() === 0) {
  t.usuarios.insertMany([
    { username: "admin", rol: "admin",   email: "admin@tienda.lab",
      password_hash: "$2b$12$Jh5TgE1MuVb115xfufnlHuxS.NfkbuD52EM4Ytl/iOLR0dp7u/x7e" },
    { username: "alice", rol: "cliente", email: "alice@tienda.lab",
      password_hash: "$2b$12$RR9xXIPu3XJBqDyv2nmV/OPdcYduwufqraTf2.yQDcpeJbp8.9b.K" },
    { username: "bob",   rol: "cliente", email: "bob@tienda.lab",
      password_hash: "$2b$12$ThKt6jwOcLG.lUNWq9KByuk/te6U6eAzygyhDSU42D8KhWiF5Ejti" }
  ]);
}

if (!existe("pedidos")) {
  t.createCollection("pedidos", {
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
}
if (t.pedidos.countDocuments() === 0) {
  t.pedidos.insertMany([
    { usuario: "alice", producto: "Portátil 14\"",     cantidad: 1, importe: 899.0 },
    { usuario: "alice", producto: "Ratón inalámbrico", cantidad: 2, importe: 39.8 },
    { usuario: "bob",   producto: "Monitor 27\"",      cantidad: 1, importe: 249.0 },
    { usuario: "bob",   producto: "Teclado mecánico",  cantidad: 1, importe: 79.9 }
  ]);
}

print("atlas_seed.js: usuarios=" + t.usuarios.countDocuments() +
      " pedidos=" + t.pedidos.countDocuments());
