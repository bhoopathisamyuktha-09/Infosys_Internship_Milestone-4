export default function ErrorBanner({ message }) {
  return (
    <div className="bg-red-950/40 border border-red-800/60 rounded-xl p-4 text-xs md:text-sm text-red-200">
      <p className="font-bold mb-1 text-red-300">Couldn't load data</p>
      <p className="text-red-400">{message}</p>
      <p className="text-red-500/80 mt-2 text-xs">
        Check that the backend is running (python run.py) and reachable at the configured API URL.
      </p>
    </div>
  );
}
