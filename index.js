import 'dotenv/config'
import express from 'express'
import cors from 'cors'

const app = express()
const port = process.env.PORT;

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
    console.log("msg:server is running fine ")
}
)

app.listen(port, () => {
    console.log(`Server is running on port ${port}`)
})