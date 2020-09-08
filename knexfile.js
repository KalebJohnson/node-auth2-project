// Update with your config settings.
module.exports = {

  development: {
    client: 'sqlite3',
    connection: {
      filename: './auth1.sqlite3'
    },
    migrations: {
      directory: "./data/migrations",
    },
    useNullAsDefault: true,
    pool:{
      afterCreate: (conn, done) => {
        conn.run('PRAGMA foreign_keys = ON', done);
      },
    },
  },

};
 
