"""Recorded process relationships within one verified inventory.

Links identify rows, not proven process ancestry. PID reuse, absent objects and
inconsistent timestamps can prevent a usable parent match.
"""
from datetime import datetime, timezone


def valid_pid(value):
    return type(value) is int and 0 <= value <= 2 ** 32 - 1


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


class ProcessIndex:
    def __init__(self, records):
        self.rows, self.by_pid, self.parents = {}, {}, {}
        times, parent_ids = {}, {}
        for ordinal, values in enumerate(records, 1):
            pid = values.get('PID')
            name = next((values[k] for k in ('ImageFileName', 'COMM', 'NAME')
                         if isinstance(values.get(k), str) and values[k].strip()), 'Unnamed process')
            row = {'id': ordinal, 'pid': pid, 'name': name}
            self.rows[ordinal] = row
            if valid_pid(pid):
                self.by_pid[pid] = None if pid in self.by_pid else row
            parent_ids[ordinal] = values.get('PPID')
            created = next((value for k in ('CreateTime', 'CREATION TIME', 'Start Time')
                            if (value := timestamp(values.get(k))) is not None), None)
            times[ordinal] = (created, timestamp(values.get('ExitTime')))
        for ordinal, row in self.rows.items():
            ppid = parent_ids[ordinal]
            parent = self.by_pid.get(ppid) if valid_pid(ppid) else None
            status = 'Unavailable'
            if valid_pid(ppid):
                if ppid == 0:
                    status = 'No recorded parent'
                elif ppid == row['pid']:
                    status = 'Self-reference'
                elif ppid not in self.by_pid:
                    status = 'Not in inventory'
                elif parent is None:
                    status = 'Ambiguous'
                else:
                    created, exited = times[ordinal]
                    parent_created, parent_exited = times[parent['id']]
                    pairs = ((created, exited), (parent_created, parent_exited),
                             (parent_created, created), (created, parent_exited))
                    status = 'Timing conflict' if any(a and b and a > b for a, b in pairs) else 'matched'
            self.parents[ordinal] = {**(parent if status == 'matched' else {'id': None, 'pid': ppid}), 'status': status}
        # Corrupt or inconsistent inventories must not offer circular ancestry.
        visited = set()
        for start in self.rows:
            path, positions, current = [], {}, start
            while current is not None and current not in visited:
                if current in positions:
                    for member in path[positions[current]:]:
                        self.parents[member].update(id=None, status='Cyclic reference')
                    break
                positions[current] = len(path)
                path.append(current)
                current = self.parents[current]['id']
            visited.update(path)

    def unique(self, pid):
        return self.by_pid.get(pid) if valid_pid(pid) else None

    def annotate(self, table):
        for row in [*table['rows'], *([table['selected']] if table['selected'] else [])]:
            row['parent'] = dict(self.parents[row['id']])
        table['children'] = [dict(row) for ordinal, row in self.rows.items()
                             if table['selected'] and self.parents[ordinal]['id'] == table['selected']['id']]

