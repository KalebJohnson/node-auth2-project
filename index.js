const express = require("express")
const usersRouter = require("./users/usersRouter")
const db = require("./data/config")

const server = express()
const port = process.env.PORT || 5000

server.use(express.json())
server.use(usersRouter)

server.use((err, req, res, next) => {
	console.log(err)
	
	res.status(500).json({
		message: "Something went wrong",
	})
})

server.listen(port, () => {
	console.log(`Running at http://localhost:${port}`)
})