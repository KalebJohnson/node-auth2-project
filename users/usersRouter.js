const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const Users = require("./usersModel")
const restrict = require("./usersMiddleware")

const router = express.Router()

router.get("/users", restrict(), async (req, res, next) => {
	try {
		res.json(await Users.find())
	} catch(err) {
		next(err)
	}
})

router.post("/register", async (req, res, next) => {
	try {
		const { username, password } = req.body
		const user = await Users.findBy({ username }).first()

		if (user) {
			return res.status(409).json({
				message: "Username is already taken",
			})
		}

		const newUser = await Users.add({
			username,
			// hash the password with a time complexity of "14"
			password: await bcrypt.hash(password, 5),
		})

		res.status(201).json(newUser)
	} catch(err) {
		next(err)
	}
})

router.post("/login", async (req, res, next) => {
	try {
		const { username, password } = req.body
		const user = await Users.findBy({ username }).first()
		
		if (!user) {
			return res.status(401).json({
				message: "Invalid Credentials",
			})
		}

		// compare the plain text password from the request body to the
		// hash we have stored in the database. returns true/false.
		const passwordValid = await bcrypt.compare(password, user.password)

		// check if hash of request body password matches the hash we already have
		if (!passwordValid) {
			return res.status(401).json({
				message: "Invalid Credentials",
			})
		}

		// generate a new JSON web token
		const token = jwt.sign({
			userID: user.id,
			userRole: user.department, // this value would normally come from the database
		}, "I know this shouldn't be here")


		res.json({
            message: `Welcome ${user.username}!`,
            token
		})
	} catch(err) {
		next(err)
	}
})



router.delete("/users/:id", async (req, res, next) => {
	try {
		await Users.findById(req.params.id).del()
		res.status(204).end()
	} catch (error) {
		next(error)
	}
})


module.exports = router