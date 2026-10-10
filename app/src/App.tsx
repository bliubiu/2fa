import { useSession } from "./store";
import EntryList from "./components/EntryList";
import UnlockScreen from "./components/UnlockScreen";

/** 会话状态机切换：锁定 → 解锁屏；已解锁 → 条目列表。 */
export default function App() {
  const status = useSession((s) => s.status);
  return status === "locked" ? <UnlockScreen /> : <EntryList />;
}
