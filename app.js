/* Imporações de pacotes */

require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

//dando inicio ao express na aplicação
const app = express()

//Config Json para express
app.use(express.json())

//Models = Requisição de usuário
const User = require('./models/User')

//Rota pública para usuário (Open Route)
app.get('/', (req, rest) => {
    rest.status(200).json({ msg: 'Bem vindo a minha API' })
})

//Rota privada (Private Route)
app.get('/user/:id', checkToken, async (req, res) => {

const id = req.params.id

//Checando se o usuário existe
const user = await User.findById(id, '-password') //o -password esconde a senha para retorno

if(!user){
    return res.status(404).json({msg : 'Usuário não encontrado!'})
}

// Retorna o usuário encontrado
res.status(200).json({user});
 
});

//Funcção para checar se o token está correto
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

if(!token){
    return res.status(401).json({msg: 'Acesso negado!'})
}

try{

    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()

} catch(error){
    res.status(400).json({msg: "Token inválido"})
}

}

//----------Registrar usuário
app.post(`/auth/register`, async (req, res) => {

    const { name, email, password, confirmpassword } = req.body

    //valdidações
    if (!name) {
        return res.status(422).json({ msg: `O nome é obrigatório` })
    }

    if (!email) {
        return res.status(422).json({ msg: `O email é obrigatório` })
    }


    if (!password) {
        return res.status(422).json({ msg: `A senha é obrigatória` })
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: `As senhas não conferem` })
    }

    //Verificação se o usuário existe, utilizando uma querry do DB
    const userExist = await User.findOne({ email: email })

    if (userExist) {
        return res.status(422).json({ msg: `Por favor, utilize outro e-mail!` })
    }

    //Criação de senha
    const salt = await bcrypt.genSalt(12) //dificultando o script para segurança
    const passwordHash = await bcrypt.hash(password, salt)

    //Criação de usuário
    const user = new User({
        name, 
        email, 
        password: passwordHash, 
    }) 

    try {
        await user.save()
        res.status(201).json({ msg: 'Usuário criado com sucesso!' })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!',
        })
    }
})

//----------Login de usuário
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body

    //validações
    if (!email) {
        return res.status(422).json({ msg: `O email é obrigatório` })
    }

    if (!password) {
        return res.status(422).json({ msg: `A senha é obrigatória` })
    }

    //Checando se o usuário é existente na plataforma
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    //Checando se as senhas conferem
    const checkPassword = await bcrypt.compare(password, user.password) //user.password compara com a senha que o usu[ario enviou ao se registrar

    if (!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida!' })
    }

    try {

        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        );

        res.status(200).json({msg: 'Autenticação realizada com sucesso', token})

    } catch (error) {
        console.log(error)
        res.status(500).json({
            msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!',
        });

    }

})


//Credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.xf7md.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(() => {
    app.listen(3000) //iniciando a aplicação no servidor local
    console.log('Conectou ao banco!')

})
    .catch((err) => console.log((err)))

