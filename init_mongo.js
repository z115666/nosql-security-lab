// Datos de laboratorio para el BASELINE INSEGURO.
// Contraseñas en texto claro a propósito: es una de las malas prácticas que se
// documentan (RGPD art. 32: el responsable debe cifrar o seudonimizar).
db = db.getSiblingDB("tienda");

db.usuarios.drop();
db.usuarios.insertMany([
  { username: "admin", password: "S3cr3t!",  rol: "admin",   email: "admin@tienda.lab" },
  { username: "alice", password: "alice123", rol: "cliente", email: "alice@tienda.lab" },
  { username: "bob",   password: "bob123",   rol: "cliente", email: "bob@tienda.lab" }
]);

db.pedidos.drop();
db.pedidos.insertMany([
  { usuario: "alice", producto: "Portátil 14\"",      cantidad: 1, importe: 899.0 },
  { usuario: "alice", producto: "Ratón inalámbrico",  cantidad: 2, importe: 39.8 },
  { usuario: "bob",   producto: "Monitor 27\"",       cantidad: 1, importe: 249.0 },
  { usuario: "bob",   producto: "Teclado mecánico",   cantidad: 1, importe: 79.9 }
]);

print("init_mongo.js: " + db.usuarios.countDocuments() + " usuarios, " +
      db.pedidos.countDocuments() + " pedidos");
