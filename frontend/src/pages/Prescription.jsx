import { useParams } from 'react-router-dom'

const Prescription = () => {
    const { userId }= useParams()
    const imageId = "1XbkwZuTso_wMXr8wbxwRXQVoJZSz2S75"
    const recetaSrc = `https://drive.google.com/uc?export=view&id=${imageId}`
    const recetaLink = `https://drive.google.com/file/d/${imageId}/view?usp=sharing`

    return (
        <div>
            <h1 className="text-3xl font-bold">Receta médica de {userId}</h1>
            <p className="my-4">Haz click en el siguiente enlace para obtener la receta médica que deberás presentar en la farmacia</p>
            <img src={recetaSrc} alt="Receta médica" />
            <div className="my-6">
                <a href={recetaLink}
                target="_blank"
                className="bg-blue-500 py-2 px-4 rounded-md hover:bg-blue-400 transition-colors text-white">
                Obtener receta
                </a>
            </div>
        </div>
    )
}

export default Prescription