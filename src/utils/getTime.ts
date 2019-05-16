export default function getTime(time: Date | string | null): number | null {
  return time ? new Date(time).getTime() : null;
}
