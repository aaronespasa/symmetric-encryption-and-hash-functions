import { useState } from "react"
import { Link } from 'react-router-dom'
import SignInBox from "../components/SignInBox"
import ErrorMessage from "../components/ErrorMessage"

const SignUp = () => {
  const [errorMessage, setErrorMessage] = useState(null)

  return (
    <SignInBox>
        <h1 className="text-3xl font-bold mb-6">Registrarse</h1>
        <div className="max-w-md mt-4 mb-10">
            <p className="mb-4">Para guardar la contraseña, se genera un hash utilizando el algoritmo de SHA256 y ese hash se cifra utilizando AES</p>
            <p>Ten en cuenta que tu contraseña deberá tener:</p>
            <p> - Al menos 8 caracteres</p>
            <p> - Al menos 1 número</p>
            <p> - Al menos 1 letra mayúscula</p>
            <p> - Al menos 1 letra minúscula</p>
            <p> - Al menos 1 caracter especial</p>
        </div>
        <form className="mb-6" method="POST">
            <input className="block w-full py-1 px-2 outline-none" type="text" name="username" id="username" placeholder="Nombre de usuario" />
            <input className="block w-full py-1 px-2 my-2 outline-none" type="password" name="password" id="password" placeholder="Contraseña" />
            <input className="block w-full py-1 px-2 my-2 outline-none" type="password" name="password" id="password" placeholder="Contraseña de nuevo" />
            {errorMessage && <ErrorMessage message={errorMessage} />}
            <button className="bg-blue-400 text-white py-2 px-20 hover:bg-blue-300 transition-colors " type="submit">Registrarse</button>
        </form>
        <div>¿Ya tienes cuenta? &nbsp;
            <Link className="font-bold text-blue-500 hover:text-blue-400" to="/login">Inicia Sesión</Link>
        </div>
    </SignInBox>
  )
}

export default SignUp