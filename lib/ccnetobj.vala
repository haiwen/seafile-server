

namespace Ccnet {


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

} // namespace
