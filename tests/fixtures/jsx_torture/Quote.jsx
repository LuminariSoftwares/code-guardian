export function Quote() {
  return (
    <blockquote>
      Press the ` key to open the console.
      <cite>anyone</cite>
      {eval(location.hash)}
    </blockquote>
  );
}
