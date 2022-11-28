import express, { response } from "express";
import users from "./database";
import { hash, compare } from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import jwt from 'jsonwebtoken'

const app = express()
app.use(express.json())

// ---- Middleware ---- \\

const verifyAuthMiddleware = (request, response, next) => {
    const authToken = request.headers.authorization

    if(!authToken){
        return response.status(409).json({message: "Missing authorization token"})
    }

    const token = authToken.split(" ")[1]

    return jwt.verify(token, "CHAVE", (error, decoded) => {
        if(error){
            return response.status(401).json({message: "Invalid token"})
        }

        request.user = {
            uuid: decoded.sub
        }

        return next()
    })
}

const verifyUuidMiddleware = (request, response, next) => {
    const userIndex = users.findIndex(user => user.uuid === request.user.uuid)

    if(userIndex === -1){
        return response.status(404).json({
            message: 'User not found!'
        })
    }

    request.user = {
        userIndex: userIndex,
        uuid: request.user.uuid
    }

    return next()
}

// ---- Service ---- \\

const listUserService = (requestUser, uuid) => {
    const admin = users.find(user => user.uuid === requestUser.uuid)
    console.log(admin)
    console.log(requestUser.uuid)
    if(admin.isAdmin === true){
        return [200, users]

    } else {

        return [403, {message: "Missing authorization headers"}]
    }

}

const createUserService = async (body) => {
    const foundUser = users.find(user => user.email === body.email)

    if(foundUser){
        return [209, {message: "Email já esta em uso"}]
    }

    const hashendPassword = await hash(body.password, 8)

    let isAdmin = false

    if(users.length === 0){
        isAdmin = true
    }

    const newUser = {
        name: body.name,
        email: body.email,
        password: hashendPassword,
        uuid: uuidv4(),
        createdAt: new Date(),
        updatedAt: new Date(),
        isAdmin: isAdmin
    }

    users.push(newUser)
    return [201, newUser]
}

const loginUserService = async (userLogin) => {
    const user = users.find(user => user.email === userLogin.email)

    if(!user){
        return [401, {message: "Email ou senha estão incorretos"}]
    }

    const passwordMatch = await compare(userLogin.password, user.password)

    if(!passwordMatch){
        return [401, {message: "Email ou senha estão incorretos"}]
    }
        const token = jwt.sign(
        {
            email: user.email
        },
        "CHAVE",
        {
            expiresIn: "20m",
            subject: user.uuid
        }
    )

    return [200, {token}]
}

const profileUserService = (uuid) => {
    const myProfile = users.find(user => user.uuid === uuid)

    const userReturn = {
        name: myProfile.name,
        email:myProfile.email,
        createdOn: myProfile.createdAt,
        updatedOn: myProfile.updatedAt,
        isAdm: myProfile.isAdmin
    }

    return [200, userReturn]
}

const updateUserService = (request) => {

    const admin = users.find(user => user.uuid === request.user.uuid)

    if(admin.isAdmin){
        const foundUser = users.findIndex(user => user.uuid === request.params.uuid)
           
        const userEmail = users.find(user => user.email === request.body.email)

        if(userEmail){
            return [209, {message: "Email já está em uso"}]
        }

        const updateUser = users.find((user, index) => {
            if(index === foundUser){
                user.name = request.body.name
                user.email = request.body.email
                user.updatedAt = new Date()
            }
        })

        return [200, users[foundUser]]
    } else if (!admin.isAdmin && request.user.uuid === request.params.uuid) {
        const foundUser = users.findIndex(user => user.uuid === request.params.uuid)
           
        const updateUser = users.find((user, index) => {
            if(index === foundUser){
                user.name = request.body.name
                user.email = request.body.email
                user.updatedAt = new Date()
            }
        })
       
        return [200, users[foundUser]]
    }

    return [403, {message: "Missing authorization headers"}]

}

const deleteUserService = (requestUser, uuid) => {
    const admin = users.find(user => user.uuid === requestUser.uuid)

    if(admin.isAdmin){
        const userDelete = users.findIndex(user => user.uuid === uuid)
        users.splice(userDelete, 1)
        return [204, {}]

    } else if (!admin.isAdmin && requestUser.uuid === uuid) {
        const userDelete = users.findIndex(user => user.uuid === uuid)
        users.splice(userDelete, 1)
        return [204, {}]
    }

    return [403, {message: "Missing authorization headers"}]
}

// ---- Controller ---- \\

const listUserController = (request, response) => {
    const requestUser = request.user
    const uuid = request.params.uuid
    const [ status, data ] = listUserService(requestUser, uuid)
    return response.status(status).json(data)
}

const createUserController = async (request, response) => {
    const [ status, data ] = await createUserService(request.body)
    return response.status(status).json(data)
}

const loginUserController = async (request, response) => {
    const [ status, data ] = await loginUserService(request.body)
    return response.status(status).json(data)
}

const profileUserController = (request, response) => {
    const [ status, data ] = profileUserService(request.user.uuid)
    return response.status(status).json(data)
}

const updateUserController = (request, response) => {
    const [ status, data ] = updateUserService(request)
    return response.status(status).json(data)
}

const deleteUserController = (request, response) => {
    const requestUser = request.user
    const uuid = request.params.uuid
    const [ status, data ] = deleteUserService(requestUser, uuid) 
    return response.status(status).json(data)
}

// ---- Routes ---- \\

app.get('/users', verifyAuthMiddleware, verifyUuidMiddleware, listUserController)
app.post('/users', createUserController)
app.post('/login', loginUserController)
app.get('/profile', verifyAuthMiddleware, profileUserController)
app.patch('/users/:uuid', verifyAuthMiddleware, verifyUuidMiddleware, updateUserController)
app.delete('/users/:uuid', verifyAuthMiddleware, verifyUuidMiddleware, deleteUserController)



app.listen(3000, () => {
    console.log('Servidor rodando na porta 3000')
})

export default app