"""A recorded PPID match must not manufacture ancestry from ambiguous records."""
import pytest

from sifted_core.memory_processes import ProcessIndex


@pytest.mark.parametrize('parent,child,extra,status', [
    ({}, {}, [], 'matched'),
    ({'CreateTime': '2024-01-01T10:00:00Z'}, {'CreateTime': '2024-01-01T11:00:00+01:00'}, [], 'matched'),
    ({'CreateTime': 'Unreadable'}, {'CreateTime': None}, [], 'matched'),
    ({}, {'PPID': 0}, [], 'No recorded parent'),
    ({}, {'PPID': 999}, [], 'Not in inventory'),
    ({}, {'PPID': 42}, [], 'Self-reference'),
    ({}, {'PPID': True}, [], 'Unavailable'),
    ({}, {'PPID': [4]}, [], 'Unavailable'),
    ({}, {'PPID': '4'}, [], 'Unavailable'),
    ({}, {'PPID': -1}, [], 'Unavailable'),
    ({}, {'PPID': 2 ** 32}, [], 'Unavailable'),
    ({}, {}, [{'PID': 4}], 'Ambiguous'),
    ({'CreateTime': '2024-01-02'}, {'CreateTime': '2024-01-01'}, [], 'Timing conflict'),
    ({'ExitTime': '2024-01-01'}, {'CreateTime': '2024-01-02'}, [], 'Timing conflict'),
    ({'CreateTime': '2024-01-02', 'ExitTime': '2024-01-01'}, {}, [], 'Timing conflict'),
    ({}, {'CreateTime': '2024-01-02', 'ExitTime': '2024-01-01'}, [], 'Timing conflict'),
    ({'PPID': 42}, {}, [], 'Cyclic reference'),
])
def test_recorded_parent_resolution(parent, child, extra, status):
    index = ProcessIndex([{'PID': 4, 'PPID': 0, 'ImageFileName': 'System', **parent},
                          {'PID': 42, 'PPID': 4, 'ImageFileName': 'child.exe', **child}, *extra])
    table = {'rows': [{'id': 2}], 'selected': {'id': 1}}
    index.annotate(table)
    match = table['rows'][0]['parent']
    assert match['status'] == status
    assert match['id'] == (1 if status == 'matched' else None)
    assert [row['pid'] for row in table['children']] == ([42] if status == 'matched' else [])


@pytest.mark.parametrize('column', ['ImageFileName', 'COMM', 'NAME'])
def test_cross_platform_names_and_exact_row_references(column):
    index = ProcessIndex([{'PID': 0, 'PPID': 0, column: 'idle'}, {'PID': 21, 'PPID': 0, column: 'parent'},
                          {'PID': 42, 'PPID': 21, column: 'child'}, {'PID': 42, 'PPID': 21, column: 'remnant'}])
    assert index.unique(21) == {'id': 2, 'pid': 21, 'name': 'parent'}
    assert index.unique(42) is None
    assert index.unique(True) is None
    assert index.unique([21]) is None
    assert index.parents[1]['id'] is None  # PID 0 is not its own parent.
    table = {'rows': [{'id': 3}, {'id': 4}], 'selected': {'id': 2}}
    index.annotate(table)
    assert [r['id'] for r in table['children']] == [3, 4]  # Distinct records, never collapsed by PID.
    assert all(r['parent']['name'] == 'parent' for r in table['rows'])


def test_cycles_are_blocked_without_hiding_unrelated_records():
    index = ProcessIndex([{'PID': 1, 'PPID': 2}, {'PID': 2, 'PPID': 3}, {'PID': 3, 'PPID': 1},
                          {'PID': 4, 'PPID': 0}, {'PID': 5, 'PPID': 4}])
    assert all(index.parents[i]['status'] == 'Cyclic reference' for i in (1, 2, 3))
    assert index.parents[5]['id'] == 4


@pytest.mark.parametrize('column', ['CreateTime', 'CREATION TIME', 'Start Time'])
def test_native_creation_time_fields_detect_conflicts(column):
    index = ProcessIndex([{'PID': 4, column: '2024-01-02T00:00:00Z'},
                          {'PID': 42, 'PPID': 4, column: '2024-01-01T00:00:00Z'}])
    assert index.parents[2]['status'] == 'Timing conflict' and index.parents[2]['id'] is None
