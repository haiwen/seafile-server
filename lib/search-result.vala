// compile this file with `valac --pkg posix repo.vala -C -H repo.h`

namespace Seafile {

public class SearchResult: Object {

    public string _path;
    public string path {
        get { return _path; }
        set { _path = value; }
    }

    public int64  size { get; set; }
    public int64  mtime { get; set; }
    public bool is_dir { set; get; }
}

} // namespace
