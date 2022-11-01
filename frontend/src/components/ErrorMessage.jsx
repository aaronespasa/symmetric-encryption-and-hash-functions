const ErrorMessage = ({ message }) => {
  return (
    <div className="bg-red-400 w-full block mb-2 rounded-sm shadow-sm">
        <p className="text-white text-sm text-center py-2">{message}</p>
    </div>
  )
}

export default ErrorMessage