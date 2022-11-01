import { Link } from 'react-router-dom'
import webLogo from "../assets/webLogo.svg"

const Navbar = () => {
    return (
        <nav className="flex justify-between items-center py-4 px-6 bg-white border-b-4 border-blue-500 mb-10">
            <div className="flex items-center">
                <Link to="/">
                    <img className="h-8 w-8 hover:scale-95 transition-transform" src={webLogo} alt="logo" />
                </Link>
            </div>
            <div className="flex items-center">
                <Link className="mr-6 hover:text-gray-700 transition-all hover:scale-95" to="/login">Iniciar Sesión</Link>
                <Link className="mr-6 hover:text-gray-700 transition-all hover:scale-95" to="/signup">Registrarse</Link>
            </div>
        </nav>
    )
}

export default Navbar