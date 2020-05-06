

namespace Ccnet {


public class Proc : Object {

    public string peer_name { get; set; }

    public string _name;
    public string name { 
        get { return _name; }
        set { _name = value; }
    }

    public int _ctime;
    public int ctime { 
        get { return _ctime; }
        set { _ctime = value; }
    }

    public int _dtime;   //dead time
    public int dtime {
        get { return _dtime; }
        set { _dtime = value; }
    }

}

public class EmailUser : Object {

    public int id { get; set; }
    public string email { get; set; }
    public bool is_staff { get; set; }
    public bool is_active { get; set; }
    public int64 ctime { get; set; }
    public string source { get; set; }
    public string role { get; set; }
    public string password { get; set; }
    public string reference_id { get; set; }
}

public class Group : Object {

    public int id { get; set; }
    public string group_name { get; set; }
    public string creator_name { get; set; }
    public int64 timestamp { get; set; }
    public string source { get; set; }
    public int parent_group_id { get; set; }

}

public class GroupUser : Object {

    public int group_id { get; set; }
    public string user_name { get; set; }
    public int is_staff { get; set; }
}

public class Organization : Object {

   public int org_id { get; set; }
   public string email { get; set; }
   public int is_staff { get; set; }
   public string org_name { get; set; }
   public string url_prefix { get; set; }
   public string creator { get; set; }
   public int64 ctime { get; set; }
   
}

public class PeerStat : Object {
   public string id { get; set; }
   public string name { get; set; }
   public string ip { get; set; }
   public bool encrypt { get; set; }
   public int64 last_up { get; set; }
   public int proc_num { get; set; }
}

} // namespace
